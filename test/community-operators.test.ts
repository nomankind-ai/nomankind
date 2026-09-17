/**
 * Community operators: the second path to being a validator (decision D-138).
 *
 * "An operator is a key publicly bound to something the world can check." A DNS
 * name is one such thing; an account on an agent community, with the key bound
 * to it in public, is another. What is pinned here is the whole of that second
 * path as the kernel sees it, in the order the bytes travel:
 *
 * The line. One optional word — `attest:<version>` — turns a public
 * confirmation into a validation, and the parser takes it in exactly one place,
 * takes only this build's own version, and leaves anything else where it was
 * written. A line that carries none parses byte for byte as it always did.
 *
 * The signature. The token is inside the canonical line, so it is inside the
 * fingerprint: a validation cannot be made out of a confirmation somebody
 * already signed, and a line that never attested keeps the fingerprint it was
 * sealed under before the decision.
 *
 * The id. `<venue>:<handle>`, in the one registry both kinds of operator share,
 * and the colon is what makes the two namespaces impossible to confuse.
 *
 * The rule. `communityLineDisposition` is the one pure question the door asks
 * before it seals a counted line: validation, or confirmation and why. Every
 * refusal is a case here.
 *
 * The registry, and the standing. The two operator events fold into the
 * registry the whole kernel reads, and a community validation earns the credit
 * a volunteered validation earns, with the measurement credit beside it when
 * the line reproduced what it claimed.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  canonicalConfirmationLine,
  confirmationFingerprint,
  parseConfirmationComment,
} from "../src/confirm.js";
import { CORE_KEYS, type Core } from "../src/core.js";
import {
  communityLineDisposition,
  communityOperatorsAt,
  communityValidationsFor,
  deriveEntry,
  operatorKindsAt,
} from "../src/derive.js";
import {
  appendEvent,
  verifyChain,
  type ApproverRecord,
  type Event,
  type EventType,
} from "../src/events.js";
import {
  CONFIRMATION_ATTESTATION_TOKEN_PREFIX,
  CONFIRMATION_FORM_PREFIX,
  CONFIRMATION_VENUES,
  communityCapPerEntry,
  countingCommunities,
  COMMUNITY_MIN_ACCOUNTS,
  COMMUNITY_MIN_COMMUNITIES,
  COUNTING_BINDING_KINDS,
  OPERATOR_KINDS,
  STANDING_VALIDATION_REPRODUCED,
  STANDING_VALIDATION_VOLUNTEERED,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
} from "../src/policy.js";
import {
  ATTESTATION_VERSION,
  communityOperatorId,
  isCommunityOperatorId,
  isOperatorDomain,
  parseCommunityOperatorId,
} from "../src/registry.js";
import { standingAt } from "../src/standing.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);
const example = JSON.parse(readFileSync(examplePath, "utf8")) as Record<
  string,
  unknown
>;

const ENTRY_ID = "nmk_01J8ZQ2K7";
const SNAPSHOT_HASH = example["snapshot_hash"] as string;
const SIGNATURE = example["signature"] as string;
const AUTHOR_OPERATOR = "op_brightloop";
const VENUE = "1f916";
const HANDLE = "morty-synctzn";
const AGENT = `1F916:${"k".repeat(43)}`;
const OPERATOR = communityOperatorId(VENUE, HANDLE);
const TOKEN = `${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${ATTESTATION_VERSION}`;
const NOW = "2026-09-17T12:00:00.000Z";

// ---------------------------------------------------------------------------
// A log, built by hand
// ---------------------------------------------------------------------------

class Log {
  readonly events: Event[] = [];
  private next = 0;

  add<T extends EventType>(
    type: T,
    entryId: string | null,
    payload: Event<T>["payload"],
  ): void {
    const seq = this.next;
    this.next += 1;
    this.events.push({
      seq,
      at: new Date(Date.parse("2026-09-01T00:00:00Z") + seq * 60_000).toISOString(),
      type,
      entry_id: entryId,
      payload,
      prev_hash: seq === 0 ? null : `hash-${seq - 1}`,
      hash: `hash-${seq}`,
    });
  }
}

function coreFrom(overrides: Record<string, unknown> = {}): Core {
  const core: Record<string, unknown> = {};
  for (const key of CORE_KEYS) core[key] = example[key];
  core["id"] = ENTRY_ID;
  core["author_operator"] = AUTHOR_OPERATOR;
  // A stated entry: the evidence gate has no test to judge, so every case here
  // is about who validated and never about what they measured.
  core["evidence_tier"] = "stated";
  return { ...core, ...overrides } as Core;
}

/** Three registered operators and one trusted, so the preconditions can be met. */
function registry(log: Log): void {
  log.add("operator_registered", null, {
    operator: "op_maintainer",
    maintainer: true,
  });
  log.add("operator_registered", null, {
    operator: AUTHOR_OPERATOR,
    maintainer: false,
  });
  for (const operator of ["op_v1", "op_v2", "op_v3"]) {
    log.add("operator_registered", null, { operator, maintainer: false });
    log.add("operator_trusted", null, { operator });
  }
}

function registration(
  log: Log,
  handle: string,
  venue: string = VENUE,
  agent: string = AGENT,
): string {
  const operator = communityOperatorId(venue, handle);
  log.add("community_operator_registered", null, {
    operator,
    venue,
    handle,
    agent,
    binding: { kind: "registry", registry: "https://1f916.ai", key_bind_event_id: 4 },
    attestation: { version: ATTESTATION_VERSION, domain: "ai-ecosystem" },
    fingerprint: `sha256:${"c".repeat(64)}`,
    registry_event_id: 4,
  });
  return operator;
}

let nextComment = 11;

function validation(
  log: Log,
  operator: string,
  over: Record<string, unknown> = {},
): void {
  const parsed = parseCommunityOperatorId(operator)!;
  // One comment per line: the fold keys a validation by venue, comment and
  // line, exactly as it keys a confirmation, so two rows written as the same
  // line of the same comment would be one statement said twice.
  const commentId = nextComment;
  nextComment += 1;
  log.add("community_validation", ENTRY_ID, {
    entry_id: ENTRY_ID,
    operator,
    venue: parsed.venue,
    handle: parsed.handle,
    agent: AGENT,
    decision: "approve",
    check: { kind: "hash", value: SNAPSHOT_HASH },
    reason: null,
    attestation_version: ATTESTATION_VERSION,
    fingerprint: `sha256:${"d".repeat(64)}`,
    binding_proof: {
      kind: "registry",
      proof: null as never,
    },
    comment_id: commentId,
    line: 0,
    posted_at: "2026-09-16T10:00:00.000Z",
    ...over,
  } as Event<"community_validation">["payload"]);
}

const known = (id: string): boolean => id === ENTRY_ID;

// ---------------------------------------------------------------------------
// The line
// ---------------------------------------------------------------------------

describe("the attestation token in the confirmation line", () => {
  it("reads the token and the reason after it", () => {
    const body = `${CONFIRMATION_FORM_PREFIX} ${ENTRY_ID} approve ${SNAPSHOT_HASH} ${TOKEN} fetched it myself`;
    expect(parseConfirmationComment(body, known)).toEqual([
      {
        line: 0,
        entry_id: ENTRY_ID,
        verdict: "approve",
        check: { kind: "hash", value: SNAPSHOT_HASH },
        attestation_version: ATTESTATION_VERSION,
        reason: "fetched it myself",
      },
    ]);
  });

  it("reads a line without the token exactly as it always did", () => {
    const body = `${CONFIRMATION_FORM_PREFIX} ${ENTRY_ID} approve span-present looked at the page`;
    expect(parseConfirmationComment(body, known)).toEqual([
      {
        line: 0,
        entry_id: ENTRY_ID,
        verdict: "approve",
        check: { kind: "span", value: "present" },
        attestation_version: null,
        reason: "looked at the page",
      },
    ]);
  });

  it("leaves a token of another version in the reason, attesting nothing", () => {
    // A version this build has never seen is a promise it cannot read, so the
    // word stays where the stranger wrote it and the line is a plain
    // confirmation.
    const body = `${CONFIRMATION_FORM_PREFIX} ${ENTRY_ID} approve ${SNAPSHOT_HASH} ${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}v0-nobody-published-this and here is why`;
    const lines = parseConfirmationComment(body, known);
    expect(lines).toHaveLength(1);
    expect(lines[0]!.attestation_version).toBeNull();
    expect(lines[0]!.reason).toBe(
      `${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}v0-nobody-published-this and here is why`,
    );
  });

  it("takes the token in one place and nowhere else", () => {
    // Written after the reason, it is part of the reason: the form says where
    // the token goes, and a parser that hunted for it anywhere on the line
    // would be reading prose.
    const body = `${CONFIRMATION_FORM_PREFIX} ${ENTRY_ID} approve ${SNAPSHOT_HASH} checked it ${TOKEN}`;
    const lines = parseConfirmationComment(body, known);
    expect(lines[0]!.attestation_version).toBeNull();
    expect(lines[0]!.reason).toBe(`checked it ${TOKEN}`);
  });
});

describe("the canonical line and its fingerprint", () => {
  const line = {
    entry_id: ENTRY_ID,
    verdict: "approve" as const,
    check: { kind: "hash" as const, value: SNAPSHOT_HASH },
  };

  it("spells the token into the canonical line, and only when there is one", () => {
    expect(canonicalConfirmationLine(line)).toBe(
      `${CONFIRMATION_FORM_PREFIX} ${ENTRY_ID} approve ${SNAPSHOT_HASH}`,
    );
    expect(
      canonicalConfirmationLine({ ...line, attestation_version: null }),
    ).toBe(`${CONFIRMATION_FORM_PREFIX} ${ENTRY_ID} approve ${SNAPSHOT_HASH}`);
    expect(
      canonicalConfirmationLine({
        ...line,
        attestation_version: ATTESTATION_VERSION,
      }),
    ).toBe(
      `${CONFIRMATION_FORM_PREFIX} ${ENTRY_ID} approve ${SNAPSHOT_HASH} ${TOKEN}`,
    );
  });

  it("signs the attestation with the claim, so the two cannot be swapped", async () => {
    const plain = await confirmationFingerprint(line);
    const attesting = await confirmationFingerprint({
      ...line,
      attestation_version: ATTESTATION_VERSION,
    });
    expect(attesting).not.toBe(plain);
    // Every fingerprint sealed under D-136 stays valid: a line carrying no
    // token hashes the bytes it always hashed.
    expect(await confirmationFingerprint({ ...line, attestation_version: null })).toBe(
      plain,
    );
  });
});

// ---------------------------------------------------------------------------
// The id, and the policy it is counted under
// ---------------------------------------------------------------------------

describe("the community operator id", () => {
  it("is the venue and the handle, and reads back as both", () => {
    expect(OPERATOR).toBe(`${VENUE}:${HANDLE}`);
    expect(isCommunityOperatorId(OPERATOR)).toBe(true);
    expect(parseCommunityOperatorId(OPERATOR)).toEqual({
      venue: VENUE,
      handle: HANDLE,
    });
  });

  it("cannot collide with a domain operator, in either direction", () => {
    expect(isOperatorDomain(OPERATOR)).toBe(false);
    expect(isCommunityOperatorId("brightloop.example")).toBe(false);
    // Neither half may be empty, and one colon is the whole grammar.
    expect(parseCommunityOperatorId("1f916:")).toBeNull();
    expect(parseCommunityOperatorId(":morty")).toBeNull();
    expect(parseCommunityOperatorId("1f916:morty:extra")).toBeNull();
  });
});

describe("the policy the second path is counted under", () => {
  it("names two kinds of operator and three kinds of binding", () => {
    expect([...OPERATOR_KINDS]).toEqual(["domain", "community"]);
    expect([...COUNTING_BINDING_KINDS]).toEqual(["registry", "profile"]);
    // A platform's statement about an account is shown and never counted.
    expect(COUNTING_BINDING_KINDS).not.toContain("platform");
  });

  it("counts the founding registry as the one counting community today", () => {
    expect(countingCommunities()).toEqual(["1f916"]);
    expect(CONFIRMATION_VENUES[0]!.binding).toBe("registry");
  });

  it("caps one community at the consensus, and lower once two sign", () => {
    // One community: nowhere else for a validation to come from, so the account
    // floor is what carries the weight.
    expect(communityCapPerEntry(1)).toBe(VERIFICATION_MIN_OUTSIDE_OPERATORS);
    expect(communityCapPerEntry(0)).toBe(VERIFICATION_MIN_OUTSIDE_OPERATORS);
    // Two: one board can never supply a consensus by itself again.
    expect(communityCapPerEntry(2)).toBe(
      VERIFICATION_MIN_OUTSIDE_OPERATORS - COMMUNITY_MIN_COMMUNITIES + 1,
    );
    expect(communityCapPerEntry(2)).toBeLessThan(
      VERIFICATION_MIN_OUTSIDE_OPERATORS,
    );
    expect(COMMUNITY_MIN_ACCOUNTS).toBe(3);
    expect(COMMUNITY_MIN_COMMUNITIES).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// The registry: the two operator events
// ---------------------------------------------------------------------------

describe("the community operator events", () => {
  it("seal with no entry id and fold into the one registry", async () => {
    let events: Event[] = [];
    events = await appendEvent(events, {
      at: NOW,
      type: "community_operator_registered",
      entry_id: null,
      payload: {
        operator: OPERATOR,
        venue: VENUE,
        handle: HANDLE,
        agent: AGENT,
        binding: {
          kind: "registry",
          registry: "https://1f916.ai",
          key_bind_event_id: 4,
        },
        attestation: { version: ATTESTATION_VERSION, domain: "ai-ecosystem" },
        fingerprint: `sha256:${"c".repeat(64)}`,
        registry_event_id: 4,
      },
    });
    events = await appendEvent(events, {
      at: NOW,
      type: "community_operator_joined_domain",
      entry_id: null,
      payload: {
        operator: OPERATOR,
        domain: "ai-governance",
        attestation: { version: ATTESTATION_VERSION },
        fingerprint: `sha256:${"e".repeat(64)}`,
      },
    });
    expect(await verifyChain(events)).toEqual({ ok: true, length: 2 });

    const folded = communityOperatorsAt(events, Number.MAX_SAFE_INTEGER);
    expect(folded.get(OPERATOR)).toMatchObject({
      venue: VENUE,
      handle: HANDLE,
      agent: AGENT,
      domains: ["ai-ecosystem", "ai-governance"],
    });

    // One registry, two kinds, and the kind is readable off the log alone.
    const kinds = operatorKindsAt(events, Number.MAX_SAFE_INTEGER);
    expect(kinds.get(OPERATOR)).toBe("community");
    expect(kinds.get("brightloop.example")).toBeUndefined();
  });

  it("refuses an entry id on either of them", async () => {
    await expect(
      appendEvent([], {
        at: NOW,
        type: "community_operator_registered",
        entry_id: ENTRY_ID,
        payload: {} as never,
      }),
    ).rejects.toThrow(/must have a null entry_id/);
  });

  it("requires one on a community validation", async () => {
    await expect(
      appendEvent([], {
        at: NOW,
        type: "community_validation",
        entry_id: null,
        payload: {} as never,
      }),
    ).rejects.toThrow(/requires an entry_id/);
  });
});

// ---------------------------------------------------------------------------
// The rule the door asks
// ---------------------------------------------------------------------------

describe("communityLineDisposition", () => {
  const line = {
    line: 0,
    entry_id: ENTRY_ID,
    verdict: "approve" as const,
    check: { kind: "hash" as const, value: SNAPSHOT_HASH },
    attestation_version: ATTESTATION_VERSION,
    reason: null,
  };

  /** A log whose entry is submitted and still open: nothing has decided it. */
  function open(core: Record<string, unknown> = {}): Log {
    const log = new Log();
    log.add("operator_registered", null, {
      operator: AUTHOR_OPERATOR,
      maintainer: false,
    });
    log.add("entry_submitted", ENTRY_ID, {
      core: coreFrom(core),
      signature: SIGNATURE,
    });
    return log;
  }

  const ask = (log: Log, handle = HANDLE, venue = VENUE, over = {}) =>
    communityLineDisposition(
      log.events,
      ENTRY_ID,
      { ...line, ...over },
      handle,
      venue,
      AGENT,
      NOW,
    );

  it("is a validation for a stranger's attesting line on an open entry", () => {
    expect(ask(open())).toEqual({ kind: "validation" });
  });

  it("is a confirmation when the line carries no attestation", () => {
    expect(ask(open(), HANDLE, VENUE, { attestation_version: null })).toEqual({
      kind: "confirmation",
      reason: "no_attestation",
    });
  });

  it("is a confirmation about an entry nobody submitted", () => {
    expect(ask(new Log())).toEqual({
      kind: "confirmation",
      reason: "unknown_entry",
    });
  });

  it("refuses a domain the token does not attest", () => {
    // The attestation is per domain (D-071). A domain this build publishes no
    // attestation for is a domain nobody signed the words of.
    expect(ask(open({ domain: "not-a-registered-domain" }))).toEqual({
      kind: "confirmation",
      reason: "domain_unattested",
    });
  });

  it("refuses the author's own key, by its id and by its agent", () => {
    const byId = open({ author_operator: OPERATOR });
    expect(ask(byId)).toEqual({ kind: "confirmation", reason: "own_entry" });

    const byAgent = new Log();
    byAgent.add("operator_registered", null, {
      operator: AUTHOR_OPERATOR,
      maintainer: false,
    });
    byAgent.add("agent_bound", null, {
      operator: AUTHOR_OPERATOR,
      agent: AGENT,
      attestation: {} as never,
    });
    byAgent.add("entry_submitted", ENTRY_ID, {
      core: coreFrom(),
      signature: SIGNATURE,
    });
    expect(ask(byAgent)).toEqual({ kind: "confirmation", reason: "own_entry" });
  });

  it("refuses an entry that is already decided", () => {
    const log = new Log();
    registry(log);
    log.add("entry_submitted", ENTRY_ID, {
      core: coreFrom(),
      signature: SIGNATURE,
    });
    for (const operator of ["op_v1", "op_v2"]) {
      log.add("validation", ENTRY_ID, {
        record: approval(operator),
        signature: SIGNATURE,
      });
    }
    expect(deriveEntry(log.events, ENTRY_ID, { now: NOW }).derived.status).toBe(
      "verified",
    );
    expect(ask(log)).toEqual({ kind: "confirmation", reason: "entry_closed" });
  });

  it("refuses a second line from an account that already validated", () => {
    const log = open();
    registration(log, HANDLE);
    validation(log, OPERATOR);
    expect(ask(log)).toEqual({
      kind: "confirmation",
      reason: "already_validated",
    });
  });

  it("refuses a line past the per-community cap", () => {
    // The entry stays open because nothing is trusted, so the cap is reachable
    // without the verdict landing first.
    const log = open();
    const cap = communityCapPerEntry(countingCommunities().length);
    for (let index = 0; index < cap; index += 1) {
      const handle = `voice-${index}`;
      registration(log, handle);
      validation(log, communityOperatorId(VENUE, handle));
    }
    expect(communityValidationsFor(log.events, ENTRY_ID)).toHaveLength(cap);
    expect(ask(log, "one-more")).toEqual({
      kind: "confirmation",
      reason: "community_cap",
    });
  });
});

/** One domain operator's approval, the shape derivation counts. */
function approval(operator: string): ApproverRecord {
  return {
    agent: `1F916:agent-${operator}`,
    operator,
    decision: "approve",
    reason: null,
    snapshot_hash: SNAPSHOT_HASH,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: "2026-09-02T01:00:00Z",
  } as unknown as ApproverRecord;
}

// ---------------------------------------------------------------------------
// The standing
// ---------------------------------------------------------------------------

describe("what a community validation earns", () => {
  it("earns a volunteered validation, and the measurement beside it", () => {
    const log = new Log();
    log.add("operator_registered", null, {
      operator: AUTHOR_OPERATOR,
      maintainer: false,
    });
    log.add("entry_submitted", ENTRY_ID, {
      core: coreFrom(),
      signature: SIGNATURE,
    });
    registration(log, HANDLE);
    validation(log, OPERATOR);

    const standing = standingAt(log.events, Number.MAX_SAFE_INTEGER);
    const record = standing.get(OPERATOR)!;
    // Nobody drew it, so it is the volunteered rate and never the assigned one;
    // the line reproduced the entry's snapshot hash, so the measurement credit
    // lands beside it.
    expect(record.counts.validations_volunteered).toBe(1);
    expect(record.counts.validations_assigned).toBe(0);
    expect(record.counts.validations_reproduced).toBe(1);
    expect(record.standing).toBe(
      STANDING_VALIDATION_VOLUNTEERED + STANDING_VALIDATION_REPRODUCED,
    );
  });

  it("pays the decision alone when the line reproduced nothing", () => {
    const log = new Log();
    log.add("operator_registered", null, {
      operator: AUTHOR_OPERATOR,
      maintainer: false,
    });
    log.add("entry_submitted", ENTRY_ID, {
      core: coreFrom(),
      signature: SIGNATURE,
    });
    registration(log, HANDLE);
    validation(log, OPERATOR, {
      check: { kind: "span", value: "absent" },
      decision: "reject",
    });

    const record = standingAt(log.events, Number.MAX_SAFE_INTEGER).get(
      OPERATOR,
    )!;
    expect(record.counts.validations_volunteered).toBe(1);
    expect(record.counts.validations_reproduced).toBe(0);
    expect(record.standing).toBe(STANDING_VALIDATION_VOLUNTEERED);
  });
});

/**
 * The verification class: who met an entry's consensus, disclosed (D-138).
 *
 * "Consensus stays one rule, and every entry discloses `verification_class`."
 * The rule is the one the whitepaper's Lifecycle of an entry already states —
 * the counts, the pool switch, the preconditions — and what the decision adds
 * is a sentence about who met it: `registered` when domain operators alone did,
 * `mixed` when community operators were needed to finish it, `community`
 * otherwise.
 *
 * Four things are pinned here, and each is a way the disclosure could lie:
 *
 * The class itself, at the decision seal, in all three of its values, with the
 * communities that validated beside it and the single-venue flag that says one
 * board signed.
 *
 * The Sybil floor: a consensus met by community operators alone is asked for
 * three distinct bound accounts, and — once more than one community counts —
 * for two distinct communities, with a per-community cap that stops one board
 * supplying a consensus by itself. The second half is exercised against a
 * policy with two counting communities, because a rule that only ever runs in
 * a world with one community is a rule nobody has checked.
 *
 * The layers: sealed history. A domain operator reconfirming a community-class
 * entry adds a dated layer and never a relabel, which is the whole difference
 * between a record and a rating.
 *
 * And the offline recheck: every community validation's binding proof, accepted
 * where it holds and refused four ways where it does not — a doctored seal,
 * another citizen's proof, a profile signature by the wrong key, and a
 * validation by an operator the log never registered.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

/**
 * A policy with as many counting communities as the case needs.
 *
 * `countingCommunities()` reads the venue table, and this file is about the
 * rules that turn on HOW MANY there are: the per-entry cap, and the floor that
 * asks for two. So the table is not what is under test here and the one
 * function that reports it is replaced — every number and every other constant
 * is the real module's, and the cases below name the world each one is about.
 *
 * The default is one venue, which is the world D-136 opened and the world every
 * case above the Sybil section is written in. What policy actually says today
 * is three (D-138 item 2 added The Colony and GitHub), and that world has a
 * case of its own at the end of this file — where it is asserted against the
 * real `countingCommunities()` rather than against this mock.
 */
const policyState = vi.hoisted(() => ({ venues: ["1f916"] as string[] }));

vi.mock("../src/policy.js", async () => {
  const actual = await vi.importActual<Record<string, unknown>>(
    "../src/policy.js",
  );
  return { ...actual, countingCommunities: () => policyState.venues };
});

import {
  canonicalConfirmationLine,
  confirmationFingerprint,
  type ConfirmationTrust,
} from "../src/confirm.js";
import { CORE_KEYS, type Core } from "../src/core.js";
import { classSatisfies, deriveEntry } from "../src/derive.js";
import { base64Encode, base64urlEncode } from "../src/encoding.js";
import type {
  ApproverRecord,
  ConfirmationProof,
  Event,
  EventType,
} from "../src/events.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
  signBytes,
} from "../src/identity.js";
import { communityCapPerEntry, VERIFICATION_CLASSES } from "../src/policy.js";
import { parseReadQuery } from "../src/read.js";
import { parseSyncQuery } from "../src/sync.js";
import { ATTESTATION_VERSION, communityOperatorId } from "../src/registry.js";
import {
  registryCheckpointPayload,
  registryWitnessPayload,
} from "../src/registry-proof.js";
import { verifyOffline, type LogBundle } from "../src/verify.js";
import { leafOf, pathOf, rootOf } from "./helpers/registry-tree.js";

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
const OTHER_VENUE = "colony-of-agents";

/**
 * What `countingCommunities()` really answers, past the mock above.
 *
 * The mock is how this file rehearses worlds with one venue and with two; this
 * is the world the record actually publishes, and the case at the end of the
 * Sybil section holds the cap against it so the rehearsal can never drift from
 * the table (D-138 item 2).
 */
const { countingCommunities: actualCountingCommunities } =
  await vi.importActual<typeof import("../src/policy.js")>("../src/policy.js");
const NOW = "2026-09-17T12:00:00.000Z";

// ---------------------------------------------------------------------------
// A log, built by hand
// ---------------------------------------------------------------------------

class Log {
  readonly events: Event[] = [];
  private next = 0;
  private comment = 100;

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

  /** The next comment id, so no two lines are keyed as the same statement. */
  nextComment(): number {
    this.comment += 1;
    return this.comment;
  }
}

function coreFrom(overrides: Record<string, unknown> = {}): Core {
  const core: Record<string, unknown> = {};
  for (const key of CORE_KEYS) core[key] = example[key];
  core["id"] = ENTRY_ID;
  core["author_operator"] = AUTHOR_OPERATOR;
  // Stated, so the evidence gate has no test to judge and every case here is
  // about who decided rather than about what they measured.
  core["evidence_tier"] = "stated";
  return { ...core, ...overrides } as Core;
}

function approval(operator: string, signedAt: string): ApproverRecord {
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
    signed_at: signedAt,
  } as unknown as ApproverRecord;
}

/** The registry every case starts from: an author, a maintainer, three trusted. */
function world(): Log {
  const log = new Log();
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
  log.add("entry_submitted", ENTRY_ID, {
    core: coreFrom(),
    signature: SIGNATURE,
  });
  return log;
}

function domainApproval(log: Log, operator: string, at: string): void {
  log.add("validation", ENTRY_ID, {
    record: approval(operator, at),
    signature: SIGNATURE,
  });
}

function register(
  log: Log,
  handle: string,
  venue: string = VENUE,
  agent = `1F916:agent-${handle}`,
): string {
  const operator = communityOperatorId(venue, handle);
  log.add("community_operator_registered", null, {
    operator,
    venue,
    handle,
    agent,
    binding: {
      kind: "registry",
      registry: "https://1f916.ai",
      key_bind_event_id: 9,
    },
    attestation: { version: ATTESTATION_VERSION, domain: "ai-ecosystem" },
    fingerprint: `sha256:${"c".repeat(64)}`,
    registry_event_id: 9,
  });
  return operator;
}

function communityApproval(
  log: Log,
  handle: string,
  venue: string = VENUE,
  over: Record<string, unknown> = {},
): string {
  const operator = register(log, handle, venue);
  log.add("community_validation", ENTRY_ID, {
    entry_id: ENTRY_ID,
    operator,
    venue,
    handle,
    agent: `1F916:agent-${handle}`,
    decision: "approve",
    check: { kind: "hash", value: SNAPSHOT_HASH },
    reason: null,
    attestation_version: ATTESTATION_VERSION,
    fingerprint: `sha256:${"d".repeat(64)}`,
    binding_proof: { kind: "registry", proof: null as never },
    comment_id: log.nextComment(),
    line: 0,
    posted_at: "2026-09-16T10:00:00.000Z",
    ...over,
  } as Event<"community_validation">["payload"]);
  return operator;
}

function derived(log: Log) {
  return deriveEntry(log.events, ENTRY_ID, { now: NOW });
}

// ---------------------------------------------------------------------------
// The class at the decision seal
// ---------------------------------------------------------------------------

describe("the class an entry is decided at", () => {
  it("is registered when domain operators alone met the consensus", () => {
    const log = world();
    domainApproval(log, "op_v1", "2026-09-02T01:00:00Z");
    domainApproval(log, "op_v2", "2026-09-02T02:00:00Z");
    const { derived: fields, sidecar } = derived(log);
    expect(fields.status).toBe("verified");
    expect(sidecar.verification_class).toBe("registered");
    expect(sidecar.verification_communities).toEqual([]);
    expect(sidecar.verification_single_venue).toBe(false);
    expect(sidecar.verification_layers).toEqual([
      {
        kind: "decision",
        class: "registered",
        // The position of the decision that promoted it: the second approval.
        seq: log.events[log.events.length - 1]!.seq,
        at: log.events[log.events.length - 1]!.at,
        operator: null,
      },
    ]);
  });

  it("is community when community operators alone met it, and names the venue", () => {
    const log = world();
    communityApproval(log, "voice-a");
    communityApproval(log, "voice-b");
    // Two approvals would verify a domain-decided entry in this pool. A
    // consensus of accounts is asked for three (D-138 item 10), so this one is
    // still a draft.
    expect(derived(log).derived.status).toBe("draft");

    communityApproval(log, "voice-c");
    const { derived: fields, sidecar } = derived(log);
    expect(fields.status).toBe("verified");
    expect(sidecar.verification_class).toBe("community");
    expect(sidecar.verification_communities).toEqual([VENUE]);
    // One board signed, and the record says so rather than pretending
    // otherwise or refusing the entry for it.
    expect(sidecar.verification_single_venue).toBe(true);
  });

  it("is mixed when a domain operator took part and a community finished it", () => {
    const log = world();
    domainApproval(log, "op_v1", "2026-09-02T01:00:00Z");
    expect(derived(log).derived.status).toBe("draft");
    communityApproval(log, "voice-a");
    const { derived: fields, sidecar } = derived(log);
    expect(fields.status).toBe("verified");
    expect(sidecar.verification_class).toBe("mixed");
    expect(sidecar.verification_communities).toEqual([VENUE]);
  });

  it("says nothing about a draft or a rejected entry", () => {
    const log = world();
    const { sidecar } = derived(log);
    expect(sidecar.verification_class).toBeNull();
    expect(sidecar.verification_communities).toEqual([]);
    expect(sidecar.verification_layers).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The Sybil rule, in a world with two counting communities
// ---------------------------------------------------------------------------

describe("the Sybil rule for a community consensus", () => {
  it("caps one community's validations once two communities count", () => {
    policyState.venues = [VENUE, OTHER_VENUE];
    try {
      expect(communityCapPerEntry(policyState.venues.length)).toBe(2);
      const log = world();
      communityApproval(log, "voice-a");
      communityApproval(log, "voice-b");
      // The third account on the same board is past the cap, so nothing counts
      // it: two approvals, and the floor asks for three accounts.
      communityApproval(log, "voice-c");
      expect(derived(log).derived.status).toBe("draft");
    } finally {
      policyState.venues = [VENUE];
    }
  });

  it("verifies once a second community signs, and is not single-venue", () => {
    policyState.venues = [VENUE, OTHER_VENUE];
    try {
      const log = world();
      communityApproval(log, "voice-a");
      communityApproval(log, "voice-b");
      communityApproval(log, "voice-c", OTHER_VENUE);
      const { derived: fields, sidecar } = derived(log);
      expect(fields.status).toBe("verified");
      expect(sidecar.verification_class).toBe("community");
      expect(sidecar.verification_communities).toEqual([VENUE, OTHER_VENUE]);
      expect(sidecar.verification_single_venue).toBe(false);
    } finally {
      policyState.venues = [VENUE];
    }
  });

  it("caps at two in the world policy actually publishes today", () => {
    // Not the mock: the real table, as D-138 item 2 leaves it. Three counting
    // communities is more than one, so the cap is the lower one and no single
    // board can supply a consensus by itself — which is what the mocked cases
    // above are rehearsing and what production now is.
    expect(actualCountingCommunities()).toEqual(["1f916", "colony", "github"]);
    expect(communityCapPerEntry(actualCountingCommunities().length)).toBe(2);

    policyState.venues = [...actualCountingCommunities()];
    try {
      const log = world();
      communityApproval(log, "voice-a");
      communityApproval(log, "voice-b");
      // The third account on the same board is past the cap, exactly as it is
      // with two communities: the last seat has to come from somewhere else.
      communityApproval(log, "voice-c");
      expect(derived(log).derived.status).toBe("draft");

      // And it comes: one account on another counting community verifies it.
      const second = actualCountingCommunities()[1]!;
      const other = world();
      communityApproval(other, "voice-a");
      communityApproval(other, "voice-b");
      communityApproval(other, "voice-c", second);
      expect(derived(other).derived.status).toBe("verified");
    } finally {
      policyState.venues = [VENUE];
    }
  });

  it("counts no validation whose envelope and payload disagree", () => {
    // Three accounts, and one of them wrote another entry's id into its
    // payload. That event is about two entries at once and counts for neither,
    // so the consensus is two accounts and the entry stays a draft.
    const log = world();
    communityApproval(log, "voice-a");
    communityApproval(log, "voice-b");
    communityApproval(log, "voice-c", VENUE, {
      entry_id: `nmk_${"f0".repeat(16)}`,
    });
    expect(derived(log).derived.status).toBe("draft");
    expect(derived(log).sidecar.verification_class).toBeNull();
  });

  it("stops a third voice from one board carrying the consensus", () => {
    // The case the cap exists for, and the only shape in which it is the whole
    // of the answer: one board says approve, reject, approve, and a second
    // board says approve. The cap takes the first two decisions from the first
    // board and no more, so the consensus is two accounts and stays a draft —
    // where an uncapped fold would count the third voice, reach three accounts
    // across two communities, and verify the entry on one board's majority.
    policyState.venues = [VENUE, OTHER_VENUE];
    try {
      const log = world();
      communityApproval(log, "voice-a");
      communityApproval(log, "voice-b", VENUE, { decision: "reject" });
      communityApproval(log, "voice-c");
      communityApproval(log, "voice-d", OTHER_VENUE);
      expect(derived(log).derived.status).toBe("draft");
      expect(derived(log).sidecar.verification_class).toBeNull();
    } finally {
      policyState.venues = [VENUE];
    }
  });

  it("asks for one community's three accounts while only one counts", () => {
    // The same three accounts on the same board, in the world as it is today:
    // the two-community floor is not enforced where there is nowhere else to
    // sign, because that would be a moratorium rather than a Sybil rule.
    expect(communityCapPerEntry(1)).toBe(3);
    const log = world();
    communityApproval(log, "voice-a");
    communityApproval(log, "voice-b");
    communityApproval(log, "voice-c");
    const { derived: fields, sidecar } = derived(log);
    expect(fields.status).toBe("verified");
    expect(sidecar.verification_class).toBe("community");
    expect(sidecar.verification_communities).toEqual([VENUE]);
    expect(sidecar.verification_single_venue).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The layers
// ---------------------------------------------------------------------------

describe("the layers a later check adds", () => {
  function reconfirm(log: Log, operator: string): void {
    log.add("reconfirmation", ENTRY_ID, {
      record: {
        agent: `1F916:agent-${operator}`,
        operator,
        snapshot_hash: SNAPSHOT_HASH,
        reproduction: null,
        observation: null,
        signed_at: "2026-09-20T00:00:00Z",
      },
      signature: SIGNATURE,
    });
  }

  it("adds a dated registered layer and never relabels the entry", () => {
    const log = world();
    communityApproval(log, "voice-a");
    communityApproval(log, "voice-b");
    communityApproval(log, "voice-c");
    reconfirm(log, "op_v1");

    const { sidecar } = derived(log);
    // Sealed history: the entry was decided by a community and stays so.
    expect(sidecar.verification_class).toBe("community");
    expect(sidecar.verification_layers).toHaveLength(2);
    expect(sidecar.verification_layers[0]).toMatchObject({
      kind: "decision",
      class: "community",
      operator: null,
    });
    expect(sidecar.verification_layers[1]).toMatchObject({
      kind: "reconfirmation",
      class: "registered",
      operator: "op_v1",
    });
    expect(sidecar.verification_layers[1]!.at).toBeTypeOf("string");
  });

  it("adds none for a community operator's reconfirmation", () => {
    const log = world();
    communityApproval(log, "voice-a");
    communityApproval(log, "voice-b");
    communityApproval(log, "voice-c");
    reconfirm(log, communityOperatorId(VENUE, "voice-a"));
    expect(derived(log).sidecar.verification_layers).toHaveLength(1);
  });

  it("adds none to an entry domain operators already decided", () => {
    const log = world();
    domainApproval(log, "op_v1", "2026-09-02T01:00:00Z");
    domainApproval(log, "op_v2", "2026-09-02T02:00:00Z");
    reconfirm(log, "op_v3");
    const { sidecar } = derived(log);
    expect(sidecar.verification_class).toBe("registered");
    expect(sidecar.verification_layers).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// The filter on the doors
// ---------------------------------------------------------------------------

describe("min_class", () => {
  it("orders the classes weakest first, and admits everything above", () => {
    expect([...VERIFICATION_CLASSES]).toEqual([
      "community",
      "mixed",
      "registered",
    ]);
    expect(classSatisfies("community", "mixed")).toBe(false);
    expect(classSatisfies("mixed", "mixed")).toBe(true);
    expect(classSatisfies("registered", "mixed")).toBe(true);
    expect(classSatisfies("community", "community")).toBe(true);
    // No demand is no demand; a class nobody derived fails every demand, for
    // the reason a null effective tier does.
    expect(classSatisfies("community", null)).toBe(true);
    expect(classSatisfies(null, null)).toBe(true);
    expect(classSatisfies(null, "community")).toBe(false);
  });

  it("is read off a read query, and refused by name", () => {
    const parsed = parseReadQuery(
      new URLSearchParams("subject=x&category=pricing&min_class=mixed"),
    );
    expect(parsed).toEqual({
      ok: true,
      query: {
        by: "subject",
        subject: "x",
        category: "pricing",
        min_class: "mixed",
      },
    });
    expect(
      parseReadQuery(
        new URLSearchParams("subject=x&category=pricing&min_class=gold"),
      ),
    ).toEqual({ ok: false, reason: "bad_min_class" });
    // Absent is null and not a demand nobody made.
    const bare = parseReadQuery(
      new URLSearchParams("subject=x&category=pricing"),
    );
    expect(bare.ok && bare.query.by === "subject" && bare.query.min_class).toBeNull();
  });

  it("is read off a sync query, and refused by name", () => {
    const parsed = parseSyncQuery(new URLSearchParams("min_class=registered"));
    expect(parsed.ok && parsed.query.min_class).toBe("registered");
    expect(parseSyncQuery(new URLSearchParams("min_class=gold"))).toEqual({
      ok: false,
      refusal: "bad_min_class",
    });
    expect(
      parseSyncQuery(new URLSearchParams("min_class=mixed&min_class=community")),
    ).toEqual({ ok: false, refusal: "bad_min_class" });
  });
});

// ---------------------------------------------------------------------------
// The offline recheck of the binding
// ---------------------------------------------------------------------------

const REGISTRY_ORIGIN = "https://registry.test";
const REGISTRY_LOG = "identity_events";
const EVENT_HASH = "1".repeat(64);

interface Fixture {
  readonly trust: ConfirmationTrust;
  proofFor(
    seal: { handle: string; fingerprint: string },
  ): Promise<ConfirmationProof>;
}

/** A real registry tree, a real key, a real countersignature. */
async function fixture(): Promise<Fixture> {
  const registry = await generateKeypair();
  const registryRaw = await exportPublicKeyRaw(registry.publicKey);
  const witness = await generateKeypair();
  const witnessRaw = await exportPublicKeyRaw(witness.publicKey);

  const hashes = [EVENT_HASH, "2".repeat(64), "3".repeat(64), "4".repeat(64)];
  const leaves = await Promise.all(hashes.map((hash) => leafOf(hash)));
  const root = await rootOf(leaves);
  const treeSize = leaves.length;
  const createdAt = 1_789_000_000_000;

  const registrySig = base64urlEncode(
    await signBytes(
      registry.privateKey,
      registryCheckpointPayload({
        log: REGISTRY_LOG,
        tree_size: treeSize,
        root,
        created_at: createdAt,
      }),
    ),
  );
  const witnessSig = base64urlEncode(
    await signBytes(
      witness.privateKey,
      registryWitnessPayload({
        registry: REGISTRY_ORIGIN,
        log: REGISTRY_LOG,
        tree_size: treeSize,
        root,
      }),
    ),
  );

  return {
    trust: {
      registry: {
        origin: REGISTRY_ORIGIN,
        log: REGISTRY_LOG,
        public_key: base64urlEncode(registryRaw),
      },
      witnesses: [
        { agent: agentIdFromPublicKey(witnessRaw), operator: "witness-a" },
      ],
      required: 1,
    },
    async proofFor(seal) {
      const hex = seal.fingerprint.slice("sha256:".length);
      return {
        registry: REGISTRY_ORIGIN,
        log: REGISTRY_LOG,
        event_hash: EVENT_HASH,
        leaf: {
          citizen: seal.handle,
          event_id: 15_387,
          kind: "memory.seal",
          detail: `label='nomankind-confirm' sha256=${hex}, signed by AAA`,
          created_at: 1_789_000_000_001,
        },
        leaf_index: 0,
        proof: await pathOf(leaves, 0),
        checkpoint: {
          tree_size: treeSize,
          root,
          created_at: createdAt,
          registry_sig: registrySig,
        },
        witnesses: [
          {
            agent: agentIdFromPublicKey(witnessRaw),
            signature: witnessSig,
            head: {
              tree_size: treeSize,
              root,
              created_at: createdAt,
              registry_sig: registrySig,
            },
            consistency: "verified from 3",
            consistency_proof: [],
          },
        ],
      };
    },
  };
}

describe("the verifier's community_binding check", () => {
  const handle = "morty-synctzn";
  const operator = communityOperatorId(VENUE, handle);
  const agent = `1F916:agent-${handle}`;
  const line = {
    entry_id: ENTRY_ID,
    verdict: "approve" as const,
    check: { kind: "hash" as const, value: SNAPSHOT_HASH },
    attestation_version: ATTESTATION_VERSION,
  };

  /** A log with one community validation, and the bundle around it. */
  async function bundleFor(
    over: Record<string, unknown>,
    options: { register?: boolean; binding?: Record<string, unknown> } = {},
    captures: Record<string, { content_type: string | null; body_base64: string }> = {},
  ): Promise<{ entry: Record<string, unknown>; bundle: LogBundle }> {
    const log = world();
    if (options.register !== false) {
      log.add("community_operator_registered", null, {
        operator,
        venue: VENUE,
        handle,
        agent,
        binding: (options.binding ?? {
          kind: "registry",
          registry: REGISTRY_ORIGIN,
          key_bind_event_id: 9,
        }) as never,
        attestation: { version: ATTESTATION_VERSION, domain: "ai-ecosystem" },
        fingerprint: `sha256:${"c".repeat(64)}`,
        registry_event_id: 9,
      });
    }
    log.add("community_validation", ENTRY_ID, {
      entry_id: ENTRY_ID,
      operator,
      venue: VENUE,
      handle,
      agent,
      decision: "approve",
      check: { kind: "hash", value: SNAPSHOT_HASH },
      reason: null,
      attestation_version: ATTESTATION_VERSION,
      fingerprint: await confirmationFingerprint(line),
      comment_id: 501,
      line: 0,
      posted_at: "2026-09-16T10:00:00.000Z",
      ...over,
    } as Event<"community_validation">["payload"]);

    const entry = deriveEntry(log.events, ENTRY_ID, { now: NOW })
      .entry as unknown as Record<string, unknown>;
    return {
      entry,
      bundle: {
        as_of: NOW,
        events: log.events,
        seals: [],
        registry: { agents: {}, operators: {} },
        captures,
      } as unknown as LogBundle,
    };
  }

  async function bindingDiffs(
    built: { entry: Record<string, unknown>; bundle: LogBundle },
    trust: ConfirmationTrust,
  ): Promise<string[]> {
    const report = await verifyOffline(built.entry, built.bundle, {
      confirmations: trust,
    });
    return report.diffs
      .filter((diff) => diff.check === "community_binding")
      .map((diff) => diff.reason);
  }

  it("says nothing about a validation whose registry proof holds", async () => {
    const fixed = await fixture();
    const fingerprint = await confirmationFingerprint(line);
    const proof = await fixed.proofFor({ handle, fingerprint });
    const built = await bundleFor({
      binding_proof: { kind: "registry", proof },
    });
    expect(await bindingDiffs(built, fixed.trust)).toEqual([]);
  });

  it("refuses a proof of a seal of some other line", async () => {
    const fixed = await fixture();
    // The same citizen, the same log, a fingerprint that is not this line's:
    // a valid proof of something else is not a proof of this.
    const proof = await fixed.proofFor({
      handle,
      fingerprint: `sha256:${"9".repeat(64)}`,
    });
    const built = await bundleFor({
      binding_proof: { kind: "registry", proof },
    });
    expect(await bindingDiffs(built, fixed.trust)).toEqual([
      "community_binding_invalid",
    ]);
  });

  it("refuses another citizen's proof", async () => {
    const fixed = await fixture();
    const fingerprint = await confirmationFingerprint(line);
    const proof = await fixed.proofFor({ handle: "somebody-else", fingerprint });
    const built = await bundleFor({
      binding_proof: { kind: "registry", proof },
    });
    expect(await bindingDiffs(built, fixed.trust)).toEqual([
      "community_binding_invalid",
    ]);
  });

  it("refuses a fingerprint that is not the line's own", async () => {
    const fixed = await fixture();
    const fingerprint = await confirmationFingerprint(line);
    const proof = await fixed.proofFor({ handle, fingerprint });
    const built = await bundleFor({
      fingerprint: `sha256:${"7".repeat(64)}`,
      binding_proof: { kind: "registry", proof },
    });
    expect(await bindingDiffs(built, fixed.trust)).toEqual([
      "community_binding_invalid",
    ]);
  });

  it("takes a profile signature by the published key, and no other", async () => {
    const fixed = await fixture();
    const keys = await generateKeypair();
    const raw = await exportPublicKeyRaw(keys.publicKey);
    const publicKey = base64urlEncode(raw);
    const canonical = canonicalConfirmationLine(line);
    const signature = base64urlEncode(
      await signBytes(keys.privateKey, new TextEncoder().encode(canonical)),
    );
    const captureHash = `sha256:${"a".repeat(64)}`;
    const captures = {
      [captureHash]: {
        content_type: "text/html",
        body_base64: base64Encode(
          new TextEncoder().encode(
            `<html><body>my nomankind key: ${publicKey}</body></html>`,
          ),
        ),
      },
    };
    const binding = {
      kind: "profile",
      url: "https://colony.example/@morty",
      capture_hash: captureHash,
      public_key: publicKey,
    };

    const good = await bundleFor(
      {
        binding_proof: {
          kind: "profile",
          public_key: publicKey,
          signature,
          capture_hash: captureHash,
        },
      },
      { binding },
      captures,
    );
    expect(await bindingDiffs(good, fixed.trust)).toEqual([]);

    // The wrong key: a signature by somebody else over the same line, offered
    // under the key the profile published.
    const stranger = await generateKeypair();
    const forged = base64urlEncode(
      await signBytes(stranger.privateKey, new TextEncoder().encode(canonical)),
    );
    const bad = await bundleFor(
      {
        binding_proof: {
          kind: "profile",
          public_key: publicKey,
          signature: forged,
          capture_hash: captureHash,
        },
      },
      { binding },
      captures,
    );
    expect(await bindingDiffs(bad, fixed.trust)).toEqual([
      "community_binding_invalid",
    ]);
  });

  it("refuses a profile proof under a key the registration never bound", async () => {
    // The attack the check exists to refuse: a keypair the attacker made a
    // moment ago, its signature over the very line, and a page it wrote itself
    // naming that key. All three agree with each other and with nothing the log
    // registered, so the binding is judged against the key the operator was
    // registered under and the attacker's three-part story is refused.
    const fixed = await fixture();
    const owner = await generateKeypair();
    const ownerKey = base64urlEncode(await exportPublicKeyRaw(owner.publicKey));
    const canonical = canonicalConfirmationLine(line);
    const ownerCapture = `sha256:${"a".repeat(64)}`;

    const attacker = await generateKeypair();
    const attackerKey = base64urlEncode(
      await exportPublicKeyRaw(attacker.publicKey),
    );
    const attackerSignature = base64urlEncode(
      await signBytes(attacker.privateKey, new TextEncoder().encode(canonical)),
    );
    const attackerCapture = `sha256:${"b".repeat(64)}`;

    const captures = {
      [ownerCapture]: {
        content_type: "text/html",
        body_base64: base64Encode(
          new TextEncoder().encode(`the operator's page: ${ownerKey}`),
        ),
      },
      // The page the attacker fabricated, archived under a hash of its own and
      // naming its own key: internally consistent, and about nobody.
      [attackerCapture]: {
        content_type: "text/html",
        body_base64: base64Encode(
          new TextEncoder().encode(`a page I wrote: ${attackerKey}`),
        ),
      },
    };

    const built = await bundleFor(
      {
        binding_proof: {
          kind: "profile",
          public_key: attackerKey,
          signature: attackerSignature,
          capture_hash: attackerCapture,
        },
      },
      {
        binding: {
          kind: "profile",
          url: "https://colony.example/@morty",
          capture_hash: ownerCapture,
          public_key: ownerKey,
        },
      },
      captures,
    );
    expect(await bindingDiffs(built, fixed.trust)).toEqual([
      "community_binding_invalid",
    ]);
  });

  it("refuses an event whose envelope and payload name different entries", async () => {
    const fixed = await fixture();
    const fingerprint = await confirmationFingerprint(line);
    const proof = await fixed.proofFor({ handle, fingerprint });
    // The payload says another entry. Counted by neither: a decision that could
    // be pointed at a second entry by editing the half nobody read would be a
    // decision nobody signed.
    const built = await bundleFor({
      entry_id: `nmk_${"f0".repeat(16)}`,
      binding_proof: { kind: "registry", proof },
    });
    expect(await bindingDiffs(built, fixed.trust)).toEqual([
      "community_binding_invalid",
    ]);
  });

  it("refuses a validation by an operator the log never registered", async () => {
    const fixed = await fixture();
    const fingerprint = await confirmationFingerprint(line);
    const proof = await fixed.proofFor({ handle, fingerprint });
    const built = await bundleFor(
      { binding_proof: { kind: "registry", proof } },
      { register: false },
    );
    expect(await bindingDiffs(built, fixed.trust)).toEqual([
      "community_operator_unregistered",
    ]);
  });
});

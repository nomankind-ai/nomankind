/**
 * Genesis by path 2, the account rung and the sunset (decision D-142).
 *
 * Section 11's genesis is the deadlock this file is about: verification wanted
 * "three verified operators outside the submitter's own, and a non-empty
 * trusted pool to draw the random validator from", and a record with no trusted
 * operator could therefore never verify the first entry that would have earned
 * somebody the trust. D-142 lifts the pool precondition exactly where the
 * consensus is community operators' alone — because that consensus draws nobody
 * — and puts the Sybil floor in its place.
 *
 * And it opens a rung below the key: a comment whose author the board
 * authenticated, with the comment and the author's profile captured and sealed.
 * The least reliable thing this record counts, so the scope around it is the
 * point of the decision rather than a detail of it, and every clause of that
 * scope is a case here: the tier it may count toward, the age of the account,
 * the per-community cap, the sunset it stops at, and the accounts nomankind
 * owns, which count toward nothing at any rung and never have.
 *
 * What is pinned:
 *
 * The genesis case itself — three account-bound accounts on two communities, no
 * trusted operator anywhere in the log, and a verified entry at the end of it —
 * and the three ways it is refused: too few accounts, too few communities, and
 * an entry whose tier the rung may not speak to.
 *
 * The two instants. An account made after the entry was submitted counts toward
 * nothing, and the sunset is read at the promoting decision's own `signed_at`
 * with the boundary itself already outside.
 *
 * The perimeter. A line from one of nomankind's own accounts is sealed, shown
 * with the perimeter word on it, and counted toward nothing: not the consensus,
 * not the bootstrap label, not the standing, and not the count of eligible
 * operators outside the submitter.
 *
 * The upgrade. An account that publishes a key keeps its id, its standing and
 * its marks, and its later lines stand on the key.
 *
 * And the offline recheck, which is where a reader who trusts none of this goes
 * instead: the captures, the scope, the age, the sunset, each refused by name.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { confirmationFingerprint } from "../src/confirm.js";
import { CORE_KEYS, type Core } from "../src/core.js";
import {
  communityLineDisposition,
  communityValidationsFor,
  deriveEntry,
} from "../src/derive.js";
import { base64Encode } from "../src/encoding.js";
import type { Event, EventType } from "../src/events.js";
import { snapshotHash } from "../src/normalize.js";
import {
  ACCOUNT_BINDING_SUNSET,
  ACCOUNT_BINDING_TIERS,
  BINDING_RUNGS,
  COMMUNITY_MIN_ACCOUNTS,
  COMMUNITY_MIN_COMMUNITIES,
  CONFIRMATION_VENUES,
  countingCommunities,
  PERIMETER_ACCOUNTS,
  PERIMETER_WORD,
} from "../src/policy.js";
import {
  ATTESTATION_VERSION,
  communityOperatorId,
  isPerimeterOperator,
} from "../src/registry.js";
import { standingAt } from "../src/standing.js";
import { verifyOffline, type LogBundle } from "../src/verify.js";

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
const NOW = "2026-09-17T12:00:00.000Z";

/**
 * Two of the communities the record actually counts, read off the table rather
 * than named, so a venue leaving `CONFIRMATION_VENUES` fails this file loudly
 * instead of quietly testing a world that no longer exists.
 */
const [VENUE_A, VENUE_B] = countingCommunities() as readonly string[];

/** When the entry was submitted; every account below is dated against it. */
const SUBMITTED_AT = "2026-09-05T00:00:00.000Z";
const OLD_ENOUGH = "2024-01-01T00:00:00.000Z";

// ---------------------------------------------------------------------------
// A log, built by hand
// ---------------------------------------------------------------------------

class Log {
  readonly events: Event[] = [];
  private next = 0;
  private comment = 200;

  add<T extends EventType>(
    type: T,
    entryId: string | null,
    payload: Event<T>["payload"],
    /** The sealed instant, where a case is about one; the clock otherwise. */
    at?: string,
  ): void {
    const seq = this.next;
    this.next += 1;
    this.events.push({
      seq,
      at:
        at ??
        new Date(
          Date.parse("2026-09-06T00:00:00Z") + seq * 60_000,
        ).toISOString(),
      type,
      entry_id: entryId,
      payload,
      prev_hash: seq === 0 ? null : `hash-${seq - 1}`,
      hash: `hash-${seq}`,
    });
  }

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
  core["evidence_tier"] = "stated";
  core["submitted_at"] = SUBMITTED_AT;
  return { ...core, ...overrides } as Core;
}

/**
 * The genesis registry: an author, a maintainer, and not one trusted operator.
 *
 * Which is the whole point — every case below that verifies does so with an
 * empty trusted pool, and before D-142 the precondition refused all of them at
 * the first line of `preconditionsMet`.
 */
function world(core: Core = coreFrom()): Log {
  const log = new Log();
  log.add("operator_registered", null, {
    operator: "op_maintainer",
    maintainer: true,
  });
  log.add("operator_registered", null, {
    operator: AUTHOR_OPERATOR,
    maintainer: false,
  });
  log.add("entry_submitted", ENTRY_ID, { core, signature: SIGNATURE });
  return log;
}

interface AccountOptions {
  readonly createdAt?: string;
  readonly commentHash?: string;
  readonly profileHash?: string;
}

/** One account-bound community operator, registered by its first line. */
function registerAccount(
  log: Log,
  handle: string,
  venue: string,
  options: AccountOptions = {},
): string {
  const operator = communityOperatorId(venue, handle);
  log.add("community_operator_registered", null, {
    operator,
    venue,
    handle,
    agent: `1F916:agent-${handle}`,
    binding: {
      kind: "account",
      venue,
      handle,
      comment_url: `https://example.test/${handle}/comment`,
      comment_capture_hash: options.commentHash ?? hashOf("c", handle),
      profile_url: `https://example.test/${handle}`,
      profile_capture_hash: options.profileHash ?? hashOf("p", handle),
      account_created_at: options.createdAt ?? OLD_ENOUGH,
    },
    attestation: { version: ATTESTATION_VERSION, domain: "ai-ecosystem" },
    fingerprint: `sha256:${"c".repeat(64)}`,
    registry_event_id: null,
  } as never);
  return operator;
}

/** One key-bound community operator, for the cases the rung is compared to. */
function registerKey(log: Log, handle: string, venue: string): string {
  const operator = communityOperatorId(venue, handle);
  log.add("community_operator_registered", null, {
    operator,
    venue,
    handle,
    agent: `1F916:agent-${handle}`,
    binding: {
      kind: "profile",
      url: `https://example.test/${handle}`,
      capture_hash: hashOf("k", handle),
      public_key: `key-${handle}`,
    },
    attestation: { version: ATTESTATION_VERSION, domain: "ai-ecosystem" },
    fingerprint: `sha256:${"c".repeat(64)}`,
    registry_event_id: null,
  } as never);
  return operator;
}

/** A distinct, well-formed hash per name, so no two captures collide. */
function hashOf(prefix: string, name: string): string {
  const seed = `${prefix}${name}`;
  let hex = "";
  for (let index = 0; index < 64; index += 1) {
    hex += seed.charCodeAt(index % seed.length).toString(16).slice(-1);
  }
  return `sha256:${hex}`;
}

interface LineOptions {
  readonly postedAt?: string;
  /** The instant the log sealed the line, where a case is about one. */
  readonly at?: string;
  readonly bindingKind?: "registry" | "profile" | "account";
  readonly perimeter?: string | null;
  readonly decision?: "approve" | "reject";
}

/** One counted line by an already-registered operator. */
function validate(log: Log, operator: string, options: LineOptions = {}): void {
  const [venue, handle] = operator.split(":") as [string, string];
  log.add("community_validation", ENTRY_ID, {
    entry_id: ENTRY_ID,
    operator,
    venue,
    handle,
    agent: `1F916:agent-${handle}`,
    decision: options.decision ?? "approve",
    check: { kind: "hash", value: SNAPSHOT_HASH },
    reason: null,
    attestation_version: ATTESTATION_VERSION,
    fingerprint: `sha256:${"d".repeat(64)}`,
    binding_proof: { kind: "account", proof: null } as never,
    binding_kind: options.bindingKind ?? "account",
    perimeter:
      options.perimeter === undefined
        ? PERIMETER_ACCOUNTS.includes(operator)
          ? PERIMETER_WORD
          : null
        : options.perimeter,
    comment_id: log.nextComment(),
    line: 0,
    posted_at: options.postedAt ?? "2026-09-06T10:00:00.000Z",
  } as never, options.at);
}

function derived(log: Log) {
  return deriveEntry(log.events, ENTRY_ID, { now: NOW });
}

// ---------------------------------------------------------------------------
// Genesis by path 2
// ---------------------------------------------------------------------------

describe("a consensus of accounts with no trusted pool", () => {
  it("verifies on three accounts from two communities", () => {
    const log = world();
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-b", VENUE_A));
    validate(log, registerAccount(log, "voice-c", VENUE_B));

    const { entry, sidecar } = derived(log);
    // The pool is empty and stays empty: nothing here was drawn, so there was
    // nothing to draw from and the precondition that asked for one is lifted.
    expect(sidecar.trusted_count_at_decision).toBe(0);
    expect(entry["status"]).toBe("verified");
    expect(sidecar.verification_class).toBe("community");
    expect(sidecar.verification_communities).toEqual([VENUE_A, VENUE_B]);
    // The weakest seat, which is what a reader filtering on a floor is asking
    // about: every one of these stood on an account.
    expect(sidecar.verification_binding).toBe("account");
    expect(sidecar.verification_layers).toHaveLength(1);
    expect(sidecar.verification_layers[0]).toMatchObject({
      kind: "decision",
      class: "community",
      binding: "account",
    });
  });

  it("refuses two accounts: the Sybil floor is the pool's replacement", () => {
    const log = world();
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-c", VENUE_B));

    expect(COMMUNITY_MIN_ACCOUNTS).toBe(3);
    const { entry, sidecar } = derived(log);
    expect(entry["status"]).toBe("draft");
    expect(sidecar.verification_binding).toBeNull();
  });

  it("refuses three accounts from one community while two count", () => {
    // The floor asks for two distinct communities once more than one counts,
    // and the per-community cap refuses the third seat from the same board
    // before the floor is even reached. Both are the same sentence said at two
    // heights, and this is the world the record publishes.
    expect(countingCommunities().length).toBeGreaterThan(1);
    expect(COMMUNITY_MIN_COMMUNITIES).toBe(2);

    const log = world();
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-b", VENUE_A));
    validate(log, registerAccount(log, "voice-d", VENUE_A));

    expect(derived(log).entry["status"]).toBe("draft");
  });

  it("keeps the pool precondition where a domain operator took part", () => {
    // Genesis by path 2 is exactly as wide as the case it is for. A consensus
    // a domain operator is in draws a validator, so the pool it draws from has
    // to exist — and in this log it does not.
    const log = world();
    log.add("operator_registered", null, {
      operator: "op_v1",
      maintainer: false,
    });
    log.add("validation", ENTRY_ID, {
      record: {
        agent: "1F916:agent-op_v1",
        operator: "op_v1",
        decision: "approve",
        reason: null,
        snapshot_hash: SNAPSHOT_HASH,
        assigned_random: false,
        test_accepted: null,
        reproduction: null,
        observation: null,
        signed_at: "2026-09-06T09:00:00.000Z",
      },
      signature: SIGNATURE,
    } as never);
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-c", VENUE_B));

    expect(derived(log).entry["status"]).toBe("draft");
  });
});

// ---------------------------------------------------------------------------
// The scope of the account rung
// ---------------------------------------------------------------------------

describe("what an account-bound line may count toward", () => {
  it("counts toward a stated entry and toward no observed one", () => {
    expect([...ACCOUNT_BINDING_TIERS]).toEqual(["stated"]);

    const log = world(coreFrom({ evidence_tier: "observed" }));
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-b", VENUE_A));
    validate(log, registerAccount(log, "voice-c", VENUE_B));

    // Not refused and not rejected: the lines are account statements, and an
    // entry nobody eligible has spoken for is a draft.
    const { entry, sidecar } = derived(log);
    expect(entry["status"]).toBe("draft");
    expect(sidecar.verification_binding).toBeNull();
    // Shown, all three of them, which is the other half of "counts toward
    // nothing": the record does not hide what was said.
    expect(communityValidationsFor(log.events, ENTRY_ID)).toHaveLength(3);
  });

  it("counts only an account older than the entry", () => {
    const log = world();
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-b", VENUE_A));
    // Made a minute after the entry was submitted: made for it, as far as the
    // record can tell.
    validate(
      log,
      registerAccount(log, "voice-c", VENUE_B, {
        createdAt: "2026-09-05T00:01:00.000Z",
      }),
    );

    expect(derived(log).entry["status"]).toBe("draft");
  });

  it("counts an account made the instant before the entry", () => {
    const log = world();
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-b", VENUE_A));
    validate(
      log,
      registerAccount(log, "voice-c", VENUE_B, {
        createdAt: "2026-09-04T23:59:59.999Z",
      }),
    );

    expect(derived(log).entry["status"]).toBe("verified");
  });
});

// ---------------------------------------------------------------------------
// The sunset
// ---------------------------------------------------------------------------

describe("the account rung's sunset", () => {
  const justBefore = new Date(
    Date.parse(ACCOUNT_BINDING_SUNSET) - 1,
  ).toISOString();

  function atSunset(postedAt: string) {
    const log = world();
    validate(log, registerAccount(log, "voice-a", VENUE_A), { postedAt });
    validate(log, registerAccount(log, "voice-b", VENUE_A), { postedAt });
    validate(log, registerAccount(log, "voice-c", VENUE_B), { postedAt });
    return derived(log);
  }

  it("forms a consensus one millisecond before the instant", () => {
    expect(atSunset(justBefore).entry["status"]).toBe("verified");
  });

  it("forms none at the instant itself", () => {
    // "At or after" means the boundary is already outside: a rule whose last
    // moment is ambiguous is a rule with two readings.
    expect(atSunset(ACCOUNT_BINDING_SUNSET).entry["status"]).toBe("draft");
  });

  it("leaves an entry verified before it verified forever", () => {
    // The sunset is read at the promoting decision's own position, so a
    // consensus that closed in 2026 is never asked about again — which is the
    // difference between a record and a rating.
    const log = world();
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-b", VENUE_A));
    validate(log, registerAccount(log, "voice-c", VENUE_B));
    // A fourth line, long after the sunset, changes nothing about the verdict.
    validate(log, registerAccount(log, "voice-e", VENUE_B), {
      postedAt: "2033-01-01T00:00:00.000Z",
    });

    const { entry, sidecar } = derived(log);
    expect(entry["status"]).toBe("verified");
    expect(sidecar.verification_binding).toBe("account");
  });
});

// ---------------------------------------------------------------------------
// The perimeter
// ---------------------------------------------------------------------------

describe("nomankind's own accounts", () => {
  const perimeter = PERIMETER_ACCOUNTS[0]!;

  /** The perimeter account, registered on its own venue, key-bound at that. */
  function withPerimeter(log: Log): string {
    const [venue, handle] = perimeter.split(":") as [string, string];
    registerKey(log, handle, venue);
    return perimeter;
  }

  it("names a perimeter account on its own venue", () => {
    expect(perimeter).toContain(":");
    expect(PERIMETER_ACCOUNTS.length).toBeGreaterThan(0);
  });

  it("seals and shows a perimeter line and counts it toward nothing", () => {
    const log = world();
    validate(log, withPerimeter(log));
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-c", VENUE_B));

    // Three approvals in the log; two of them counted, so no consensus.
    const { entry } = derived(log);
    expect(entry["status"]).toBe("draft");

    // Shown, with the perimeter word on it, which is the disclosure.
    const shown = communityValidationsFor(log.events, ENTRY_ID);
    expect(shown).toHaveLength(3);
    const own = shown.find((row) => row.operator === perimeter)!;
    expect(own.perimeter).toBe(PERIMETER_WORD);
    expect(shown.filter((row) => row.perimeter === null)).toHaveLength(2);
  });

  it("counts toward nothing even key-bound and even beside three others", () => {
    // Key-bound is not the question: whose account it is, is.
    const log = world();
    validate(log, withPerimeter(log));
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-b", VENUE_A));
    validate(log, registerAccount(log, "voice-c", VENUE_B));

    const { sidecar } = derived(log);
    expect(sidecar.verification_communities).not.toContain(
      perimeter.split(":")[0]! === VENUE_A ? "__never__" : "__never__",
    );
    expect(derived(log).entry["status"]).toBe("verified");
    // Three counted seats, none of them nomankind's.
    expect(sidecar.verification_binding).toBe("account");
  });

  it("is not one of the three eligible operators outside the submitter", () => {
    // Two outside operators and nomankind's own makes three ids and two
    // signers. The precondition counts signers.
    const log = world();
    const own = withPerimeter(log);
    validate(log, own);
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-b", VENUE_A));

    expect(derived(log).entry["status"]).toBe("draft");
  });

  it("earns no standing for a line that counts toward nothing", () => {
    const log = world();
    const own = withPerimeter(log);
    validate(log, own);
    validate(log, registerAccount(log, "voice-a", VENUE_A));

    const standing = standingAt(log.events, Number.MAX_SAFE_INTEGER);
    // The row exists, because the registration made an operator; what it did
    // not do is earn, because the line it made counts toward nothing.
    expect(standing.get(own)?.earned ?? 0).toBe(0);
    expect(standing.get(own)?.counts.validations_volunteered ?? 0).toBe(0);
    // And the outside account is paid for the same work, at the same rate.
    const other = standing.get(communityOperatorId(VENUE_A, "voice-a"));
    expect(other?.counts.validations_volunteered).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// The upgrade
// ---------------------------------------------------------------------------

/**
 * The upgrade, with the proof that makes it mean anything (the review of #105).
 *
 * An event carrying no proof is the record's own word that a key exists
 * somewhere, and it lifts no rung on either side of the log — which the case
 * below this one pins.
 */
function upgrade(log: Log, operator: string, withProof = true): void {
  const handle = operator.split(":")[1]!;
  log.add("community_operator_bound", null, {
    operator,
    agent: `1F916:agent-${handle}-key`,
    binding: {
      kind: "profile",
      url: `https://example.test/${handle}`,
      capture_hash: hashOf("k", handle),
      public_key: `key-${handle}`,
    },
    capture_hash: hashOf("k", handle),
    fingerprint: `sha256:${"e".repeat(64)}`,
    proof: withProof
      ? {
          kind: "profile",
          public_key: `key-${handle}`,
          signature: `sig-${handle}`,
          capture_hash: hashOf("k", handle),
        }
      : null,
  } as never);
}

describe("an account that publishes a key", () => {
  it("keeps its id, its standing and its marks, and stands on the key", () => {
    const log = world();
    const first = registerAccount(log, "voice-a", VENUE_A);
    validate(log, first);

    // The upgrade: the same operator, a stronger binding, nothing else moved.
    upgrade(log, first);

    validate(log, registerAccount(log, "voice-b", VENUE_A));
    validate(log, registerAccount(log, "voice-c", VENUE_B));

    const { entry, sidecar } = derived(log);
    expect(entry["status"]).toBe("verified");
    // The weakest seat is still an account — two of the three are — and the
    // upgrade did not relabel the line it was made after.
    expect(sidecar.verification_binding).toBe("account");

    // One operator, one id, both lines: the key did not mint a second
    // operator, which is the whole of what the upgrade promises.
    const standing = standingAt(log.events, Number.MAX_SAFE_INTEGER);
    const ids = [...standing.keys()].filter((id) => id.endsWith(":voice-a"));
    expect(ids).toEqual([first]);
    expect(standing.get(first)?.counts.validations_volunteered).toBe(1);
  });

  it("lifts the consensus to the key rung once every seat stands on one", () => {
    const log = world();
    const ids = [
      registerAccount(log, "voice-a", VENUE_A),
      registerAccount(log, "voice-b", VENUE_A),
      registerAccount(log, "voice-c", VENUE_B),
    ];
    for (const operator of ids) upgrade(log, operator);
    for (const operator of ids) {
      validate(log, operator, { bindingKind: "profile" });
    }

    const { entry, sidecar } = derived(log);
    expect(entry["status"]).toBe("verified");
    expect(sidecar.verification_binding).toBe("key");
  });

  it("lifts nothing when the upgrade carries no proof", () => {
    // A rung is a sentence about what a reader can recheck offline. An event
    // that says "there is a key now" and hands over nothing to check it against
    // is the one thing a binding exists to replace, so it moves no rung — here,
    // and in the verifier (the review of #105).
    const log = world();
    const ids = [
      registerAccount(log, "voice-a", VENUE_A),
      registerAccount(log, "voice-b", VENUE_A),
      registerAccount(log, "voice-c", VENUE_B),
    ];
    for (const operator of ids) upgrade(log, operator, false);
    for (const operator of ids) validate(log, operator);

    const { entry, sidecar } = derived(log);
    expect(entry["status"]).toBe("verified");
    expect(sidecar.verification_binding).toBe("account");
  });
});

// ---------------------------------------------------------------------------
// The rungs the read filter orders
// ---------------------------------------------------------------------------

describe("min_binding", () => {
  it("orders the rungs weakest first, as the classes are ordered", () => {
    expect([...BINDING_RUNGS]).toEqual(["account", "key"]);
  });
});

// ---------------------------------------------------------------------------
// The offline recheck
// ---------------------------------------------------------------------------


/**
 * What the verifier says about an account-bound line.
 *
 * Two kinds of check, and the difference between them is the review of #105.
 *
 * The captures are a fact about the LINE: the rung carries no signature, so the
 * two archived pages are the whole of what it proves, and a binding nobody can
 * recheck is a fault whatever the line went on to do. Those are checked on
 * every account-bound line in the bundle.
 *
 * The scope — the tier, the age of the account, the sunset — are facts about
 * COUNTING, and the verifier asks them of exactly the lines the bundle's own
 * fold counted, which is what derivation does. A line the fold left uncounted
 * moved nothing, and refusing a clone for holding a comment that changed
 * nothing is not a fault a clone can have. So the cases below pin both halves:
 * the captures refused four ways, and the scope answered with silence and an
 * uncounted line.
 */
describe("the verifier's account-binding checks", () => {
  const handle = "morty-synctzn";
  const venue = VENUE_A;
  const operator = communityOperatorId(venue, handle);
  const origin = CONFIRMATION_VENUES.find((each) => each.venue === venue)!
    .origin;
  const line = {
    entry_id: ENTRY_ID,
    verdict: "approve" as const,
    check: { kind: "hash" as const, value: SNAPSHOT_HASH },
    attestation_version: ATTESTATION_VERSION,
  };

  interface Pages {
    readonly comment: string;
    readonly profile: string;
    readonly captures: Record<
      string,
      { content_type: string | null; body_base64: string }
    >;
  }

  /**
   * Two archived pages under the hashes their own bytes produce: the comment
   * naming the entry it was read about, and the profile naming the account.
   *
   * The two tokens the verifier looks for, and not the canonical line itself —
   * a capture is whatever the venue's public door answered, and on two of the
   * three venues that is a JSON rendering rather than the raw text, so the
   * line's exact bytes may be escaped or split across fields while an opaque id
   * survives every rendering of the same content.
   */
  async function captured(over: Partial<Record<"comment" | "profile", string>> = {}): Promise<Pages> {
    const pages: Record<string, string> = {
      comment:
        over.comment ??
        `{"body":"nomankind-confirm-v1 approve ${ENTRY_ID} hash=${SNAPSHOT_HASH}"}`,
      profile:
        over.profile ??
        `{"handle":"${handle}","created_at":"${OLD_ENOUGH}"}`,
    };
    const captures: Record<
      string,
      { content_type: string | null; body_base64: string }
    > = {};
    const hashes: Record<string, string> = {};
    for (const [name, text] of Object.entries(pages)) {
      const bytes = new TextEncoder().encode(text);
      const result = await snapshotHash(bytes, "text/plain");
      const hash = result.ok ? result.hash : "";
      hashes[name] = hash;
      captures[hash] = {
        content_type: "text/plain",
        body_base64: base64Encode(bytes),
      };
    }
    return {
      comment: hashes["comment"]!,
      profile: hashes["profile"]!,
      captures,
    };
  }

  interface BundleOptions {
    readonly core?: Core;
    readonly createdAt?: string;
    readonly postedAt?: string;
    /** A hash the proof names that the bundle holds no bytes for. */
    readonly commentHash?: string;
    readonly pages?: Partial<Record<"comment" | "profile", string>>;
    readonly commentUrl?: string;
    readonly profileUrl?: string;
    readonly operatorAs?: string;
    /**
     * More lines beside the one under test, so it is a counted decision.
     *
     * `accounts` is two more of the same rung, which is the ordinary genesis
     * consensus. `keys` is three key-bound ones, which is how a consensus can
     * close after the sunset at all: the account seat is dropped from the
     * count and the key seats carry it, and the dropped seat is still one of
     * the decisions the entry was folded from.
     */
    readonly counted?: "accounts" | "keys";
  }

  /** A log with one account-bound validation, and the bundle around it. */
  async function bundleFor(options: BundleOptions = {}): Promise<{
    entry: Record<string, unknown>;
    bundle: LogBundle;
    /** The position of the line under test, so its own diffs can be read. */
    seq: number;
  }> {
    const pages = await captured(options.pages);
    const log = world(options.core ?? coreFrom());
    const id = options.operatorAs ?? operator;
    const [ownVenue, ownHandle] = id.split(":") as [string, string];
    log.add("community_operator_registered", null, {
      operator: id,
      venue: ownVenue,
      handle: ownHandle,
      agent: `1F916:agent-${ownHandle}`,
      binding: {
        kind: "account",
        venue: ownVenue,
        handle: ownHandle,
        comment_url: options.commentUrl ?? `${origin}/post/1#comment-701`,
        comment_capture_hash: pages.comment,
        profile_url: options.profileUrl ?? `${origin}/users/${ownHandle}`,
        profile_capture_hash: pages.profile,
        account_created_at: options.createdAt ?? OLD_ENOUGH,
      },
      attestation: { version: ATTESTATION_VERSION, domain: "ai-ecosystem" },
      fingerprint: `sha256:${"c".repeat(64)}`,
      registry_event_id: null,
    } as never);
    log.add("community_validation", ENTRY_ID, {
      entry_id: ENTRY_ID,
      operator: id,
      venue: ownVenue,
      handle: ownHandle,
      agent: `1F916:agent-${ownHandle}`,
      decision: "approve",
      check: { kind: "hash", value: SNAPSHOT_HASH },
      reason: null,
      attestation_version: ATTESTATION_VERSION,
      fingerprint: await confirmationFingerprint(line),
      binding_proof: {
        kind: "account",
        comment_capture_hash: options.commentHash ?? pages.comment,
        profile_capture_hash: pages.profile,
      },
      binding_kind: "account",
      perimeter: null,
      comment_id: 701,
      line: 0,
      posted_at: options.postedAt ?? "2026-09-06T10:00:00.000Z",
    } as never);
    const seq = log.events[log.events.length - 1]!.seq;

    if (options.counted === "accounts") {
      validate(log, registerAccount(log, "voice-b", VENUE_A), {
        postedAt: options.postedAt,
      });
      validate(log, registerAccount(log, "voice-c", VENUE_B), {
        postedAt: options.postedAt,
      });
    }
    if (options.counted === "keys") {
      for (const [name, board] of [
        ["voice-b", VENUE_A],
        ["voice-c", VENUE_B],
        ["voice-d", VENUE_B],
      ] as const) {
        validate(log, registerKey(log, name, board), {
          postedAt: options.postedAt,
          bindingKind: "profile",
        });
      }
    }

    const entry = deriveEntry(log.events, ENTRY_ID, { now: NOW })
      .entry as unknown as Record<string, unknown>;
    return {
      entry,
      seq,
      bundle: {
        as_of: NOW,
        events: log.events,
        seals: [],
        registry: { agents: {}, operators: {} },
        captures: pages.captures,
      } as unknown as LogBundle,
    };
  }

  /**
   * What the verifier says about the ONE line under test.
   *
   * The lines a case adds to make that one counted are fixtures and not the
   * subject: their own bindings are hashes with no bytes behind them, so the
   * verifier says the same thing about each of them, every time, and reading
   * those answers back would be reading the fixture rather than the rule.
   */
  async function bindingDiffs(built: {
    entry: Record<string, unknown>;
    bundle: LogBundle;
    seq: number;
  }): Promise<string[]> {
    const report = await verifyOffline(built.entry, built.bundle);
    return report.diffs
      .filter(
        (diff) =>
          diff.check === "community_binding" &&
          diff.field === `/events/${built.seq}`,
      )
      .map((diff) => diff.reason);
  }

  // The captures: a fact about the line, checked on every one of them.

  it("says nothing about a line whose two captures hold", async () => {
    expect(await bindingDiffs(await bundleFor())).toEqual([]);
  });

  it("refuses a comment capture the bundle holds no bytes for", async () => {
    const built = await bundleFor({
      commentHash: `sha256:${"1".repeat(64)}`,
    });
    expect(await bindingDiffs(built)).toContain(
      "account_binding_proof_invalid",
    );
  });

  it("refuses a comment capture that is some other page of the board", async () => {
    // Archived, hashing back to its own bytes, and about another entry: the
    // hash proves bytes were kept, and only the bytes prove which line.
    const built = await bundleFor({
      pages: { comment: '{"body":"nomankind-confirm-v1 approve nmk_somewhere"}' },
    });
    expect(await bindingDiffs(built)).toContain(
      "account_binding_proof_invalid",
    );
  });

  it("refuses a profile capture that is some other account's", async () => {
    const built = await bundleFor({
      pages: { profile: '{"handle":"somebody-else","created_at":"2020-01-01T00:00:00Z"}' },
    });
    expect(await bindingDiffs(built)).toContain(
      "account_binding_proof_invalid",
    );
  });

  it("refuses a page on a site the venue does not answer on", async () => {
    // Parsed and not prefix-matched: `https://1f916.ai.evil.test` starts with
    // no origin it is not on.
    const built = await bundleFor({
      profileUrl: `${origin}.evil.test/users/${handle}`,
    });
    expect(await bindingDiffs(built)).toContain(
      "account_binding_proof_invalid",
    );
  });

  // The scope: a fact about counting, asked of the lines the fold counted.

  it("says nothing about an out-of-scope line, which counted toward nothing", async () => {
    // An observed entry is not one the rung may speak to, so the fold counts
    // the line toward nothing — and a clone holding a comment that changed
    // nothing is not a clone somebody edited.
    const built = await bundleFor({
      core: coreFrom({ evidence_tier: "observed" }),
      counted: "accounts",
    });
    expect(await bindingDiffs(built)).toEqual([]);
    expect(built.entry["status"]).toBe("draft");
  });

  it("says nothing about a too-new account, which counted toward nothing", async () => {
    const built = await bundleFor({
      createdAt: "2026-09-06T00:00:00.000Z",
      counted: "accounts",
    });
    expect(await bindingDiffs(built)).toEqual([]);
    expect(built.entry["status"]).toBe("draft");
  });

  it("refuses a counted account line in a consensus that closed after the sunset", async () => {
    // The sunset is read at the promoting decision's instant, in the verifier
    // as in the fold (the review of #105): a line posted in 2026 that is among
    // the decisions of a consensus closing in 2032 stood on a rung that had
    // expired by the time the consensus formed.
    const after = new Date(Date.parse(ACCOUNT_BINDING_SUNSET) + 60_000)
      .toISOString();
    const built = await bundleFor({ postedAt: after, counted: "keys" });
    expect(await bindingDiffs(built)).toContain(
      "account_binding_after_sunset",
    );
  });

  it("says nothing about a perimeter line the fold refused to count", async () => {
    // Every perimeter line sealed before D-142 carries no perimeter word,
    // because the field did not exist; the fold counts none of them, and a
    // check on the word alone failed every published mirror (the review of
    // #105). What names the fault is the counting, and the fold never counts
    // one — so the refusal is the invariant, stated, and silent here.
    const built = await bundleFor({ operatorAs: PERIMETER_ACCOUNTS[0]! });
    expect(await bindingDiffs(built)).not.toContain("perimeter_line_counted");
  });
});

// ---------------------------------------------------------------------------
// The review of #105
// ---------------------------------------------------------------------------

describe("the id an account speaks under", () => {
  it("is trimmed and case-folded, so one account is never two operators", () => {
    // An id is a key this record groups by — the Sybil floor counts distinct
    // ones, the cap counts them per board — and two spellings of one account
    // would be two seats for one party.
    expect(communityOperatorId("GitHub", " Nomankind-AI ")).toBe(
      "github:nomankind-ai",
    );
    expect(communityOperatorId(VENUE_A, "Voice-A")).toBe(
      communityOperatorId(VENUE_A, "voice-a"),
    );
  });

  it("holds the perimeter against a differently spelled id", () => {
    // The hole this closes: `Nomankind-AI` walking past `PERIMETER_ACCOUNTS`
    // and being counted into a consensus.
    const own = PERIMETER_ACCOUNTS[0]!;
    expect(isPerimeterOperator(own)).toBe(true);
    expect(isPerimeterOperator(own.toUpperCase())).toBe(true);
    expect(isPerimeterOperator(` ${own} `)).toBe(true);
    expect(isPerimeterOperator(`${own}-not`)).toBe(false);
  });

  it("counts a differently spelled perimeter line toward nothing", () => {
    const own = PERIMETER_ACCOUNTS[0]!;
    const [venue, handle] = own.split(":") as [string, string];
    const log = world();
    // Registered under the shouted spelling, which mints the folded id.
    registerKey(log, handle.toUpperCase(), venue.toUpperCase());
    validate(log, own, { perimeter: null });
    validate(log, registerAccount(log, "voice-a", VENUE_A));
    validate(log, registerAccount(log, "voice-b", VENUE_A));

    expect(derived(log).entry["status"]).toBe("draft");
  });
});

describe("a decision that dates itself", () => {
  it("is judged by the later of what it says and when it was sealed", () => {
    // `signed_at` is the signer's own word and nothing checks it, so a key
    // wanting one more account-bound consensus after the rung closed could
    // simply date its approval to 2031. A decision cannot have been taken after
    // it was sealed, so the sealed instant is the floor (the review of #105).
    const beforeSunset = new Date(
      Date.parse(ACCOUNT_BINDING_SUNSET) - 60_000,
    ).toISOString();
    const afterSunset = new Date(
      Date.parse(ACCOUNT_BINDING_SUNSET) + 60_000,
    ).toISOString();

    const log = world();
    validate(log, registerAccount(log, "voice-a", VENUE_A), {
      postedAt: beforeSunset,
      at: afterSunset,
    });
    validate(log, registerAccount(log, "voice-b", VENUE_A), {
      postedAt: beforeSunset,
      at: afterSunset,
    });
    validate(log, registerAccount(log, "voice-c", VENUE_B), {
      postedAt: beforeSunset,
      at: afterSunset,
    });

    expect(derived(log).entry["status"]).toBe("draft");
  });
});

describe("the per-community cap", () => {
  it("counts the seats that still count and not the ones the sunset dropped", () => {
    // One board's cap is two. An account seat the sunset has dropped occupies
    // nothing, so the board's second seat is free — and a cap that went on
    // holding its place would keep it empty forever on a rule that had already
    // expired (the review of #105).
    const after = new Date(
      Date.parse(ACCOUNT_BINDING_SUNSET) + 60_000,
    ).toISOString();
    const log = world();
    validate(log, registerAccount(log, "voice-a", VENUE_A), { postedAt: after });
    validate(log, registerKey(log, "voice-b", VENUE_A), {
      postedAt: after,
      bindingKind: "profile",
    });
    validate(log, registerKey(log, "voice-c", VENUE_B), {
      postedAt: after,
      bindingKind: "profile",
    });
    validate(log, registerKey(log, "voice-d", VENUE_B), {
      postedAt: after,
      bindingKind: "profile",
    });

    const { entry, sidecar } = derived(log);
    expect(entry["status"]).toBe("verified");
    // Three key seats carried it, the account seat carried nothing, and the
    // floor a reader filters on says so.
    expect(sidecar.verification_binding).toBe("key");
  });
});

describe("what the door seals for an account-bound line", () => {
  const line = {
    line: 0,
    entry_id: ENTRY_ID,
    verdict: "approve" as const,
    check: { kind: "hash" as const, value: SNAPSHOT_HASH },
    attestation_version: ATTESTATION_VERSION,
    signature: null,
    reason: null,
  };

  function accountBinding(createdAt = OLD_ENOUGH) {
    return {
      kind: "account" as const,
      venue: VENUE_A,
      handle: "voice-a",
      comment_url: "https://example.test/voice-a/comment",
      comment_capture_hash: hashOf("c", "voice-a"),
      profile_url: "https://example.test/voice-a",
      profile_capture_hash: hashOf("p", "voice-a"),
      account_created_at: createdAt,
    };
  }

  function disposition(core: Core, createdAt = OLD_ENOUGH) {
    const log = world(core);
    return communityLineDisposition(
      log.events,
      ENTRY_ID,
      line,
      "voice-a",
      VENUE_A,
      "1F916:agent-voice-a",
      NOW,
      accountBinding(createdAt),
    );
  }

  it("seals a validation where the rung may speak", () => {
    expect(disposition(coreFrom())).toEqual({ kind: "validation" });
  });

  it("falls back to a confirmation on an entry the rung may not speak to", () => {
    // The door and the fold ask one rule (`accountScopeRefusal`), so a line the
    // door seals as a validation is a line the fold counts — which is the
    // three-way disagreement the review found between sweep, derive and
    // verifier.
    expect(disposition(coreFrom({ evidence_tier: "observed" }))).toEqual({
      kind: "confirmation",
      reason: "account_out_of_scope",
    });
  });

  it("falls back to a confirmation for an account younger than the entry", () => {
    expect(disposition(coreFrom(), "2026-09-06T00:00:00.000Z")).toEqual({
      kind: "confirmation",
      reason: "account_too_new",
    });
  });

  it("says nothing about the rung for a key-bound line", () => {
    const log = world(coreFrom({ evidence_tier: "observed" }));
    expect(
      communityLineDisposition(
        log.events,
        ENTRY_ID,
        line,
        "voice-a",
        VENUE_A,
        "1F916:agent-voice-a",
        NOW,
        {
          kind: "profile",
          url: "https://example.test/voice-a",
          capture_hash: hashOf("k", "voice-a"),
          public_key: "key-voice-a",
        },
      ),
    ).toEqual({ kind: "validation" });
  });
});

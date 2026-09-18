/**
 * The derivation stamp, and the rows it cannot reach (decisions D-135, D-142).
 *
 * `DERIVATION_VERSION` is how a stored row and a fresh derivation of the same
 * events are kept from disagreeing: the sweep re-derives every row whose stamp
 * is not the current one, and the export then publishes what the verifier will
 * confirm. It only works if it moves when the kernel moves, and twice now it
 * has not:
 *
 * D-135 found three demo rows still saying `verified` after the QA of
 * 2026-09-13 narrowed the verification precondition, and session 3 (#102) added
 * `attestation_version` to the public-confirmation view without bumping the
 * stamp, so the demo mirror of 2026-09-18 published a `/sidecar/confirmations`
 * that a fresh fold did not produce. Both were caught by a human reading a
 * FAIL line, which is not a mechanism.
 *
 * So the first half of this file is one: a fingerprint of the shape the kernel
 * derives, recorded against the version string it was taken under. Change the
 * shape without bumping the stamp and the fingerprint under the current version
 * no longer matches; bump the stamp without recording the fingerprint and there
 * is nothing under the new version to match. The two have to move together,
 * which is the whole of what the stamp promises.
 *
 * The second half is the rows the stamp cannot reach. A re-derivation runs the
 * derived entry past the published v0.7 schema first, and a v0.6 core has no
 * `domain` and no `version` and never will — so a legacy row is refused there
 * and keeps the verdict it was given, whatever the rules do afterwards. That is
 * deliberate, and it means `verify-mirror` comparing such a row's
 * consensus-decided fields against today's fold is comparing a row the record
 * has promised never to rewrite against rules it has promised never to apply to
 * it. Those rows are reported legacy with the fields named; a legacy row
 * differing anywhere else is a FAIL exactly as before.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { CORE_KEYS, type Core } from "../src/core.js";
import {
  CONSENSUS_DECIDED,
  frozenFieldsOf,
} from "../src/cli/verify-mirror.js";
import { DERIVATION_VERSION, deriveEntry } from "../src/derive.js";
import type { Event, EventType } from "../src/events.js";
import { sha256Hex } from "../src/hash.js";
import { ATTESTATION_VERSION, communityOperatorId } from "../src/registry.js";

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
const VENUE = "1f916";

// ---------------------------------------------------------------------------
// The shape stamp
// ---------------------------------------------------------------------------

/**
 * The fingerprint of the derived shape, per version string.
 *
 * One row, and a row is added only when the stamp moves. This is the table a
 * reviewer looks at: a diff that touches it and not `DERIVATION_VERSION`, or
 * `DERIVATION_VERSION` and not it, is the mistake D-135 found written down in
 * advance.
 */
const SHAPE_BY_VERSION: Readonly<Record<string, string>> = Object.freeze({
  "2026-09-18-d142":
    "8ac8e09fb1f93676bb9c0bc35a089af011e6e7274e54bf3cbfcbcd7629dea523",
});

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
      at: new Date(
        Date.parse("2026-09-06T00:00:00Z") + seq * 60_000,
      ).toISOString(),
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
  core["evidence_tier"] = "stated";
  core["submitted_at"] = "2026-09-05T00:00:00.000Z";
  return { ...core, ...overrides } as Core;
}

function approval(operator: string, signedAt: string): Record<string, unknown> {
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
  };
}

/**
 * One entry carrying as much of the derived shape as a fixture can reach: a
 * domain consensus with a community line beside it, a public confirmation, a
 * dated layer from a reconfirmation, and a revalidation.
 *
 * What it cannot reach is named rather than hidden — an empty `disputes` or
 * `failure_reports` array carries no element shape, so those two element types
 * are outside this stamp. The fields the two misses of D-135 and #102 were in
 * are inside it, which is what it is for.
 */
function richLog(): Log {
  const log = new Log();
  log.add("operator_registered", null, {
    operator: "op_maintainer",
    maintainer: true,
  } as never);
  log.add("operator_registered", null, {
    operator: AUTHOR_OPERATOR,
    maintainer: false,
  } as never);
  for (const operator of ["op_v1", "op_v2", "op_v3"]) {
    log.add("operator_registered", null, {
      operator,
      maintainer: false,
    } as never);
    log.add("operator_trusted", null, { operator } as never);
  }
  log.add("entry_submitted", ENTRY_ID, {
    core: coreFrom(),
    signature: SIGNATURE,
  } as never);

  const handle = "voice-a";
  const community = communityOperatorId(VENUE, handle);
  log.add("community_operator_registered", null, {
    operator: community,
    venue: VENUE,
    handle,
    agent: `1F916:agent-${handle}`,
    binding: {
      kind: "profile",
      url: "https://example.test/voice-a",
      capture_hash: `sha256:${"a".repeat(64)}`,
      public_key: "key-voice-a",
    },
    attestation: { version: ATTESTATION_VERSION, domain: "ai-ecosystem" },
    fingerprint: `sha256:${"c".repeat(64)}`,
    registry_event_id: null,
  } as never);
  log.add("community_validation", ENTRY_ID, {
    entry_id: ENTRY_ID,
    operator: community,
    venue: VENUE,
    handle,
    agent: `1F916:agent-${handle}`,
    decision: "approve",
    check: { kind: "hash", value: SNAPSHOT_HASH },
    reason: null,
    attestation_version: ATTESTATION_VERSION,
    fingerprint: `sha256:${"d".repeat(64)}`,
    binding_proof: { kind: "profile" },
    binding_kind: "profile",
    perimeter: null,
    comment_id: 301,
    line: 0,
    posted_at: "2026-09-06T10:00:00.000Z",
  } as never);

  log.add("validation", ENTRY_ID, {
    record: approval("op_v1", "2026-09-06T11:00:00.000Z"),
    signature: SIGNATURE,
  } as never);
  log.add("validation", ENTRY_ID, {
    record: approval("op_v2", "2026-09-06T12:00:00.000Z"),
    signature: SIGNATURE,
  } as never);

  log.add("public_confirmation", ENTRY_ID, {
    entry_id: ENTRY_ID,
    venue: VENUE,
    handle: "somebody",
    verdict: "approve",
    check: { kind: "hash", value: SNAPSHOT_HASH },
    reason: null,
    comment_id: 44,
    line: 0,
    posted_at: "2026-09-06T13:00:00.000Z",
    registry_event_id: null,
    counted: true,
    attestation_version: null,
  } as never);

  log.add("reconfirmation", ENTRY_ID, {
    record: {
      ...approval("op_v3", "2026-09-06T14:00:00.000Z"),
      decision: "confirm",
    },
    signature: SIGNATURE,
  } as never);

  log.add("revalidation_requested", ENTRY_ID, {
    entry_id: ENTRY_ID,
    operator: "op_v1",
    agent: "1F916:agent-op_v1",
    reason: "a check",
    requested_at: "2026-09-06T15:00:00.000Z",
  } as never);
  return log;
}

/**
 * Every key path in a derived value, arrays folded to their element shapes.
 *
 * Paths and not values: what this is a fingerprint of is the SHAPE the kernel
 * derives — which fields exist and where — because that is what a stored row
 * and a fresh fold can disagree about without either of them being wrong.
 */
function shapePaths(value: unknown, prefix: string, into: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value) shapePaths(item, `${prefix}[]`, into);
    return;
  }
  if (typeof value !== "object" || value === null) {
    into.add(prefix);
    return;
  }
  for (const key of Object.keys(value as Record<string, unknown>)) {
    shapePaths(
      (value as Record<string, unknown>)[key],
      `${prefix}/${key}`,
      into,
    );
  }
}

async function shapeFingerprint(): Promise<string> {
  const log = richLog();
  const { entry, sidecar } = deriveEntry(log.events, ENTRY_ID, { now: NOW });
  const paths = new Set<string>();
  shapePaths(entry, "entry", paths);
  shapePaths(sidecar, "sidecar", paths);
  return sha256Hex(new TextEncoder().encode([...paths].sort().join("\n")));
}

describe("the derivation stamp", () => {
  it("moves whenever the derived shape moves", async () => {
    const fingerprint = await shapeFingerprint();
    const recorded = SHAPE_BY_VERSION[DERIVATION_VERSION];

    // A version with no fingerprint recorded for it is a bump nobody finished:
    // the sweep will rewrite every row, and nothing says what it will write.
    expect([DERIVATION_VERSION, recorded ?? "(nothing recorded)"]).toEqual([
      DERIVATION_VERSION,
      fingerprint,
    ]);
  });

  it("names the version the rules last moved under", () => {
    // The value is the date and the decision, which is the only thing a reader
    // of a stored row ever has to compare.
    expect(DERIVATION_VERSION).toMatch(/^\d{4}-\d{2}-\d{2}-d\d+$/);
    expect(Object.keys(SHAPE_BY_VERSION)).toContain(DERIVATION_VERSION);
  });

  it("carries the two fields the misses of D-135 and #102 were in", async () => {
    const log = richLog();
    const { sidecar } = deriveEntry(log.events, ENTRY_ID, { now: NOW });
    // #102 added this one to the confirmation view and bumped nothing.
    expect(sidecar.confirmations[0]).toHaveProperty("attestation_version");
    // D-142 adds this one, and the stamp above moves with it.
    expect(sidecar).toHaveProperty("verification_binding");
  });
});

// ---------------------------------------------------------------------------
// The rows a re-derivation cannot reach
// ---------------------------------------------------------------------------

describe("a legacy row the fold no longer reaches", () => {
  const sidecarOnly = [
    { field: "/sidecar/verification_class", reason: "mismatch" },
    { field: "/sidecar/verification_layers", reason: "mismatch" },
  ];

  it("names the fields the record invented after the row was sealed", () => {
    expect(frozenFieldsOf(sidecarOnly, true)).toEqual([
      "/sidecar/verification_class",
      "/sidecar/verification_layers",
    ]);
  });

  it("holds the verdict out of that list, so an edited status still fails", () => {
    // The hole the review of #105 found: `status` and `verified_at` are the
    // verdict itself, and a verdict nobody rechecks is a verdict anybody can
    // type in. They are checked against `legacyVerdict` instead — the rule the
    // record decided them by — so they are deliberately not freezable here.
    expect(CONSENSUS_DECIDED).not.toContain("/entry/status");
    expect(CONSENSUS_DECIDED).not.toContain("/entry/verified_at");
    expect(
      frozenFieldsOf(
        [{ field: "/entry/status", reason: "mismatch" }, ...sidecarOnly],
        true,
      ),
    ).toBeNull();
  });

  it("is a difference like any other on a v0.7 record", () => {
    // The record rewrites a v0.7 row when the rules move, so a v0.7 row that
    // disagrees with the fold is a row somebody edited or a sweep that has not
    // run — and either is a FAIL a reader is owed.
    expect(frozenFieldsOf(sidecarOnly, false)).toBeNull();
  });

  it("is a difference when anything outside the list differs too", () => {
    // The carve-out is about which fields the fold decides, never about which
    // rows are allowed to differ: one edited claim beside them and the whole
    // row is a FAIL again.
    expect(
      frozenFieldsOf(
        [...sidecarOnly, { field: "/entry/claim", reason: "mismatch" }],
        true,
      ),
    ).toBeNull();
  });

  it("says nothing about a clean row", () => {
    expect(frozenFieldsOf([], true)).toBeNull();
  });

  it("names only fields the consensus fold decides", () => {
    // Every path in the list is one the fold writes and a v0.6 row cannot have
    // rewritten. A path that is not — a claim, a citation, a seal — would be a
    // field an edit could hide behind, which is the one thing this must not be.
    for (const field of CONSENSUS_DECIDED) {
      expect(field.startsWith("/sidecar/")).toBe(true);
    }
    expect(CONSENSUS_DECIDED).toContain("/sidecar/verification_binding");
    expect(CONSENSUS_DECIDED).not.toContain("/entry/claim");
    expect(CONSENSUS_DECIDED).not.toContain("/entry/snapshot_hash");
    expect(CONSENSUS_DECIDED).not.toContain("/entry/seal");
  });
});

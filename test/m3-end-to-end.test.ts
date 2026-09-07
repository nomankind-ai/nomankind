/**
 * The M3 surface as a consumer sees it: a log is built with appendEvent, the
 * chain is verified, the entry is derived, and the derived entry validates
 * against the schema. Everything below is imported from the package entry
 * point, so a missing re-export fails here rather than in a later milestone.
 *
 * The last case is the point of the chain: an edited log still derives, and it
 * derives a different answer. Only verifyChain says the log was rewritten.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  appendEvent,
  deriveEntry,
  extractCore,
  validateEntry,
  verifyChain,
  type ApproverRecord,
  type Clock,
  type Core,
  type Event,
} from "../src/index.js";

const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);
const example = JSON.parse(readFileSync(examplePath, "utf8")) as Record<
  string,
  unknown
>;

const ENTRY_ID = example["id"] as string;
const SIGNATURE = example["signature"] as string;
const HASH = example["snapshot_hash"] as string;

const MAINTAINER = "op_maintainer";
/** Three registered operators outside the submitter's own and the maintainer's. */
const OUTSIDE = ["op_northgate", "op_cindermill", "op_dryfield"] as const;

const FIRST_SIGNED_AT = "2026-09-01T15:10:00Z";
const SECOND_SIGNED_AT = "2026-09-01T16:22:00Z";

/** The fake clock. Nothing in this test reads a wall clock. */
const CLOCK: Clock = { now: "2026-09-10T00:00:00Z" };

/** Sequential event timestamps, from the same fake clock. */
function at(index: number): string {
  return new Date(
    Date.parse("2026-09-01T12:00:00Z") + index * 60_000,
  ).toISOString();
}

function approval(operator: string, signedAt: string): ApproverRecord {
  return {
    agent: `1F916:agent-${operator}`,
    operator,
    decision: "approve",
    reason: null,
    snapshot_hash: HASH,
    assigned_random: false,
    test_accepted: true,
    reproduction: null,
    observation: {
      method: "endpoint_error",
      receipt_hash: HASH,
      observed_at: "2026-09-01",
      runs: 10,
      holds: 10,
    },
    signed_at: signedAt,
  } as unknown as ApproverRecord;
}

/**
 * Four registered operators (one the maintainer), three of them trusted, the
 * example's core submitted, and two approvals from two outside operators.
 */
async function buildLog(): Promise<Event[]> {
  const core: Core = extractCore(example);
  let events: Event[] = [];
  let index = 0;
  const append = async (
    type: Parameters<typeof appendEvent>[1]["type"],
    entryId: string | null,
    payload: Parameters<typeof appendEvent>[1]["payload"],
  ) => {
    events = await appendEvent(events, {
      at: at(index),
      type,
      entry_id: entryId,
      payload,
    });
    index += 1;
  };

  await append("operator_registered", null, {
    operator: MAINTAINER,
    maintainer: true,
  });
  for (const operator of OUTSIDE) {
    await append("operator_registered", null, { operator, maintainer: false });
  }
  for (const operator of OUTSIDE) {
    await append("operator_trusted", null, { operator });
  }
  await append("entry_submitted", ENTRY_ID, { core, signature: SIGNATURE });
  await append("validation", ENTRY_ID, {
    record: approval(OUTSIDE[0], FIRST_SIGNED_AT),
    signature: SIGNATURE,
  });
  await append("validation", ENTRY_ID, {
    record: approval(OUTSIDE[1], SECOND_SIGNED_AT),
    signature: SIGNATURE,
  });
  return events;
}

/** The seq of the first validation event. */
function firstValidationSeq(events: readonly Event[]): number {
  const event = events.find((candidate) => candidate.type === "validation");
  expect(event).toBeDefined();
  return (event as Event).seq;
}

describe("M3 end to end: a sealed log derives a verified entry", () => {
  it("verifies the chain, derives verified, and validates against the schema", async () => {
    const events = await buildLog();

    expect(await verifyChain(events)).toEqual({
      ok: true,
      length: events.length,
    });

    const { entry, derived } = deriveEntry(events, ENTRY_ID, CLOCK);
    expect(derived.status).toBe("verified");
    expect(derived.verified_at).toBe(SECOND_SIGNED_AT);

    const result = validateEntry(entry);
    expect(result.ok ? [] : result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("catches an edited decision in the chain, and derives a different entry", async () => {
    const events = await buildLog();
    const edited = structuredClone(events) as Event[];
    const seq = firstValidationSeq(edited);

    const payload = edited[seq]!.payload as { record: { decision: string } };
    expect(payload.record.decision).toBe("approve");
    payload.record.decision = "reject";

    // The chain is the only thing that knows the log was rewritten.
    expect(await verifyChain(edited)).toEqual({
      ok: false,
      seq,
      reason: "bad_hash",
    });

    // Derivation reads the edited log at face value and reaches a different
    // answer: one approval against one rejection never verifies.
    const derived = deriveEntry(edited, ENTRY_ID, CLOCK).derived;
    expect(derived.status).toBe("draft");
    expect(derived.verified_at).toBeNull();
  });
});

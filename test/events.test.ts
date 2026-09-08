import { describe, expect, it } from "vitest";

import { CORE_KEYS, type Core } from "../src/core.js";
import {
  appendEvent,
  ENTRY_SCOPED_TYPES,
  EVENT_TYPES,
  eventHash,
  verifyChain,
  type ApproverRecord,
  type Event,
  type EventInput,
} from "../src/events.js";

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;

const ENTRY_ID = "entry-0001";

/** A core with exactly the seventeen schema keys; M3 treats it as opaque. */
function makeCore(id: string = ENTRY_ID): Core {
  const core: Record<string, unknown> = {
    id,
    subject: "example.com",
    category: "fact",
    claim: "The sky is blue.",
    before: null,
    after: "blue",
    effective_at: "2026-01-01T00:00:00Z",
    evidence_tier: "observation",
    evidence: null,
    observation: null,
    citation: "https://example.com/sky",
    snapshot_hash: `sha256:${"a".repeat(64)}`,
    norm_version: "1.0.0",
    supersedes: null,
    author: "agent-1",
    author_operator: null,
    submitted_at: "2026-01-02T00:00:00Z",
  };
  expect(Object.keys(core).sort()).toEqual([...CORE_KEYS].sort());
  return core as Core;
}

function approverRecord(
  decision: "approve" | "reject" = "approve",
): ApproverRecord {
  return {
    agent: "agent-2",
    operator: "operator-b",
    decision,
    reason: null,
    snapshot_hash: null,
    assigned_random: true,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: "2026-01-03T00:00:00Z",
  };
}

const inputs: EventInput[] = [
  {
    at: "2026-01-01T00:00:00Z",
    type: "operator_trusted",
    entry_id: null,
    payload: { operator: "operator-a" },
  },
  {
    at: "2026-01-02T00:00:00Z",
    type: "entry_submitted",
    entry_id: ENTRY_ID,
    payload: { core: makeCore(), signature: "sig-author" },
  },
  {
    at: "2026-01-03T00:00:00Z",
    type: "validation",
    entry_id: ENTRY_ID,
    payload: { record: approverRecord(), signature: "sig-validator" },
  },
];

async function buildLog(): Promise<Event[]> {
  let log: Event[] = [];
  for (const input of inputs) {
    log = await appendEvent(log, input);
  }
  return log;
}

/** Structural clone so a mutated fixture never shares state with the original. */
function clone(log: readonly Event[]): Event[] {
  return JSON.parse(JSON.stringify(log)) as Event[];
}

describe("event types", () => {
  it("names exactly the eleven event types", () => {
    expect(EVENT_TYPES).toEqual([
      "operator_registered",
      "operator_trusted",
      "operator_untrusted",
      "agent_bound",
      "pool_snapshot",
      "entry_submitted",
      "assignment",
      "assignment_missed",
      "validation",
      "reconfirmation",
      "dispute_upheld",
    ]);
    expect(new Set(EVENT_TYPES).size).toBe(11);
  });

  it("scopes six of them to an entry", () => {
    expect(ENTRY_SCOPED_TYPES).toEqual([
      "entry_submitted",
      "assignment",
      "assignment_missed",
      "validation",
      "reconfirmation",
      "dispute_upheld",
    ]);
    for (const type of ENTRY_SCOPED_TYPES) {
      expect(EVENT_TYPES).toContain(type);
    }
  });

  it("leaves the operator events, agent_bound included, unscoped", () => {
    for (const type of [
      "operator_registered",
      "operator_trusted",
      "operator_untrusted",
      "agent_bound",
      "pool_snapshot",
    ] as const) {
      expect(ENTRY_SCOPED_TYPES).not.toContain(type);
    }
  });
});

describe("agent_bound", () => {
  const attestation = {
    version: "nomankind-independence-v1",
    signed_at: "2026-09-07T00:00:00Z",
    signature: "c2ln",
  };

  it("appends with a null entry_id and carries the attestation verbatim", async () => {
    const log = await appendEvent([], {
      at: "2026-09-07T00:00:00Z",
      type: "agent_bound",
      entry_id: null,
      payload: { operator: "example.com", agent: "1F916:abc", attestation },
    });
    expect(log).toHaveLength(1);
    expect(log[0]!.entry_id).toBeNull();
    expect(log[0]!.payload).toEqual({
      operator: "example.com",
      agent: "1F916:abc",
      attestation,
    });
    await expect(verifyChain(log)).resolves.toEqual({ ok: true, length: 1 });
  });

  it("refuses a non-null entry_id", async () => {
    await expect(
      appendEvent([], {
        at: "2026-09-07T00:00:00Z",
        type: "agent_bound",
        entry_id: ENTRY_ID,
        payload: { operator: "example.com", agent: "1F916:abc", attestation },
      }),
    ).rejects.toThrow(/null entry_id/);
  });
});

describe("appendEvent", () => {
  it("chains three events that verify", async () => {
    const log = await buildLog();
    expect(log).toHaveLength(3);
    await expect(verifyChain(log)).resolves.toEqual({ ok: true, length: 3 });
  });

  it("starts at seq 0 with a null prev_hash and links each later event", async () => {
    const log = await buildLog();
    expect(log[0]!.seq).toBe(0);
    expect(log[0]!.prev_hash).toBeNull();
    for (let i = 1; i < log.length; i += 1) {
      expect(log[i]!.seq).toBe(i);
      expect(log[i]!.prev_hash).toBe(log[i - 1]!.hash);
    }
  });

  it("gives every event a schema-shaped hash", async () => {
    const log = await buildLog();
    for (const event of log) {
      expect(event.hash).toMatch(HASH_PATTERN);
    }
  });

  it("returns a new array and leaves the input untouched", async () => {
    const log = await buildLog();
    const snapshot = clone(log);
    const extended = await appendEvent(log, {
      at: "2026-01-04T00:00:00Z",
      type: "pool_snapshot",
      entry_id: null,
      payload: { operators: ["operator-a", "operator-b"] },
    });
    expect(extended).not.toBe(log);
    expect(extended).toHaveLength(4);
    expect(log).toHaveLength(3);
    expect(log).toEqual(snapshot);
  });

  it("refuses an unknown type", async () => {
    await expect(
      appendEvent([], {
        at: "2026-01-01T00:00:00Z",
        type: "entry_deleted",
        entry_id: null,
        payload: {},
      } as unknown as EventInput),
    ).rejects.toThrow(/unknown event type/);
  });

  it("refuses a null entry_id on an entry-scoped event", async () => {
    await expect(
      appendEvent([], {
        at: "2026-01-03T00:00:00Z",
        type: "validation",
        entry_id: null,
        payload: { record: approverRecord(), signature: "sig-validator" },
      }),
    ).rejects.toThrow(/requires an entry_id/);
  });

  it("refuses a non-null entry_id on an operator event", async () => {
    await expect(
      appendEvent([], {
        at: "2026-01-01T00:00:00Z",
        type: "operator_trusted",
        entry_id: ENTRY_ID,
        payload: { operator: "operator-a" },
      }),
    ).rejects.toThrow(/null entry_id/);
  });

  it("refuses a submission whose entry_id is not the core id", async () => {
    await expect(
      appendEvent([], {
        at: "2026-01-02T00:00:00Z",
        type: "entry_submitted",
        entry_id: "entry-9999",
        payload: { core: makeCore(), signature: "sig-author" },
      }),
    ).rejects.toThrow(/must equal payload.core.id/);
  });

  it("refuses a missing or empty at", async () => {
    await expect(
      appendEvent([], {
        at: "",
        type: "operator_trusted",
        entry_id: null,
        payload: { operator: "operator-a" },
      }),
    ).rejects.toThrow(/non-empty ISO 8601 string/);
    await expect(
      appendEvent([], {
        type: "operator_trusted",
        entry_id: null,
        payload: { operator: "operator-a" },
      } as unknown as EventInput),
    ).rejects.toThrow(/non-empty ISO 8601 string/);
  });
});

describe("eventHash", () => {
  it("is deterministic and independent of key order", async () => {
    const a = await eventHash({
      seq: 0,
      at: "2026-01-03T00:00:00Z",
      type: "validation",
      entry_id: ENTRY_ID,
      payload: { record: approverRecord(), signature: "sig-validator" },
      prev_hash: null,
    });
    const reordered = approverRecord();
    const shuffled: Record<string, unknown> = {};
    for (const key of Object.keys(reordered).reverse()) {
      shuffled[key] = (reordered as Record<string, unknown>)[key];
    }
    const b = await eventHash({
      prev_hash: null,
      payload: {
        signature: "sig-validator",
        record: shuffled as unknown as ApproverRecord,
      },
      entry_id: ENTRY_ID,
      type: "validation",
      at: "2026-01-03T00:00:00Z",
      seq: 0,
    });
    expect(b).toBe(a);
    expect(a).toMatch(HASH_PATTERN);
  });
});

describe("verifyChain", () => {
  it("accepts an empty log", async () => {
    await expect(verifyChain([])).resolves.toEqual({ ok: true, length: 0 });
  });

  it("catches an edited payload at that event's seq", async () => {
    const log = clone(await buildLog());
    const payload = log[2]!.payload as { record: ApproverRecord };
    payload.record.decision = "reject";
    await expect(verifyChain(log)).resolves.toEqual({
      ok: false,
      seq: 2,
      reason: "bad_hash",
    });
  });

  it("catches a replaced prev_hash", async () => {
    const log = clone(await buildLog());
    log[2]!.prev_hash = `sha256:${"b".repeat(64)}`;
    await expect(verifyChain(log)).resolves.toEqual({
      ok: false,
      seq: 2,
      reason: "bad_prev_hash",
    });
  });

  it("catches a seq gap", async () => {
    const log = clone(await buildLog());
    log[2]!.seq = 7;
    await expect(verifyChain(log)).resolves.toEqual({
      ok: false,
      seq: 2,
      reason: "bad_seq",
    });
  });
});

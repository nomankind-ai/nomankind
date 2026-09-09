/**
 * The delta stream (src/sync.ts).
 *
 * Whitepaper Section 8, "The delta stream": events strictly by sealed position,
 * `flatten` collapsing a supersession chain to its newest entry, and an
 * overturned entry delivered as an unlearn rather than quietly dropped.
 * Section 8, "Paying for the training path", and Section 9: each delivered
 * verified entry counts as one read.
 *
 * The parser tests are the same story as the reader's: a malformed query gets
 * one named refusal, always the same one, and a well-formed one gets defaults
 * it did not have to write. The filter tests are the other story: what the
 * stream is allowed to withhold from a trainer, and what it is never allowed to
 * withhold.
 */

import { describe, expect, it } from "vitest";

import {
  LIST_PAGE_LIMIT,
  SYNC_QUERY_PARAMETERS,
  SYNC_QUERY_REFUSALS,
  keepSyncItem,
  parseSyncQuery,
  syncItemKind,
  syncReceiptEntries,
  type Event,
  type SyncEntryState,
  type SyncQuery,
  type SyncReceiptEntry,
} from "../src/index.js";

const ENTRY_ID = "nmk_0123456789abcdef0123456789abcdef";

/** A query with every default, then whatever the test cares about. */
function query(overrides: Partial<SyncQuery> = {}): SyncQuery {
  return {
    from: 0,
    limit: LIST_PAGE_LIMIT,
    flatten: false,
    min_tier: null,
    ...overrides,
  };
}

/** One log event, only the fields the kind rule reads. */
function event(overrides: Partial<Event> = {}): Event {
  return {
    seq: 7,
    at: "2026-09-09T12:00:00.000Z",
    type: "entry_submitted",
    entry_id: ENTRY_ID,
    payload: {} as Event["payload"],
    prev_hash: null,
    hash: `sha256:${"a".repeat(64)}`,
    ...overrides,
  } as Event;
}

function state(
  status: SyncEntryState["status"],
  tier: SyncEntryState["effective_tier"] = "observed",
): SyncEntryState {
  return { status, effective_tier: tier };
}

function parsed(search: string): SyncQuery {
  const result = parseSyncQuery(new URLSearchParams(search));
  if (!result.ok) throw new Error(`expected ok, got ${result.refusal}`);
  return result.query;
}

function refusal(search: string): string {
  const result = parseSyncQuery(new URLSearchParams(search));
  if (result.ok) throw new Error(`expected a refusal for ${search}`);
  return result.refusal;
}

describe("parseSyncQuery", () => {
  it("names its parameters and its refusals, in the order they are checked", () => {
    expect(SYNC_QUERY_PARAMETERS).toEqual([
      "from",
      "limit",
      "flatten",
      "min_tier",
    ]);
    expect(SYNC_QUERY_REFUSALS).toEqual([
      "unknown_parameter",
      "bad_from",
      "bad_limit",
      "bad_flatten",
      "bad_min_tier",
    ]);
  });

  it("answers a bare sync with every default", () => {
    expect(parsed("")).toEqual({
      from: 0,
      limit: LIST_PAGE_LIMIT,
      flatten: false,
      min_tier: null,
    });
  });

  it("reads every parameter a trainer wrote", () => {
    expect(parsed("from=41&limit=5&flatten=true&min_tier=observed")).toEqual({
      from: 41,
      limit: 5,
      flatten: true,
      min_tier: "observed",
    });
    expect(parsed("flatten=false&min_tier=stated").flatten).toBe(false);
  });

  it("refuses a parameter it does not know, before anything else", () => {
    expect(refusal("cursor=7")).toBe("unknown_parameter");
    // Even when everything else is malformed too: the first check wins.
    expect(refusal("cursor=7&from=-1&limit=0&flatten=yes&min_tier=gold")).toBe(
      "unknown_parameter",
    );
  });

  it("refuses a from that is not a non-negative safe integer", () => {
    for (const bad of ["-1", "1.5", "07", "+1", "", "one", "9007199254740993"]) {
      expect(refusal(`from=${bad}`)).toBe("bad_from");
    }
    expect(parsed("from=0").from).toBe(0);
  });

  it("bounds the limit at one and at the page limit", () => {
    expect(refusal("limit=0")).toBe("bad_limit");
    expect(refusal(`limit=${LIST_PAGE_LIMIT + 1}`)).toBe("bad_limit");
    for (const bad of ["-1", "1.5", "", "all"]) {
      expect(refusal(`limit=${bad}`)).toBe("bad_limit");
    }
    expect(parsed("limit=1").limit).toBe(1);
    expect(parsed(`limit=${LIST_PAGE_LIMIT}`).limit).toBe(LIST_PAGE_LIMIT);
  });

  it("takes only the two literal spellings of flatten", () => {
    for (const bad of ["", "1", "yes", "True", "TRUE"]) {
      expect(refusal(`flatten=${bad}`)).toBe("bad_flatten");
    }
  });

  it("refuses a tier outside the schema's enum", () => {
    for (const bad of ["", "gold", "Observed"]) {
      expect(refusal(`min_tier=${bad}`)).toBe("bad_min_tier");
    }
    expect(parsed("min_tier=stated").min_tier).toBe("stated");
  });

  it("refuses a parameter given twice: two values are two questions", () => {
    expect(refusal("from=1&from=2")).toBe("bad_from");
    expect(refusal("limit=1&limit=2")).toBe("bad_limit");
    expect(refusal("flatten=true&flatten=false")).toBe("bad_flatten");
    expect(refusal("min_tier=stated&min_tier=observed")).toBe("bad_min_tier");
  });

  it("checks the four in the declared order", () => {
    expect(refusal("from=-1&limit=0&flatten=yes&min_tier=gold")).toBe(
      "bad_from",
    );
    expect(refusal("limit=0&flatten=yes&min_tier=gold")).toBe("bad_limit");
    expect(refusal("flatten=yes&min_tier=gold")).toBe("bad_flatten");
  });
});

describe("syncItemKind", () => {
  it("calls an event about no entry an event", () => {
    expect(syncItemKind(event({ type: "pool_snapshot", entry_id: null }))).toBe(
      "event",
    );
    expect(syncItemKind(event({ type: "read_count", entry_id: null }))).toBe(
      "event",
    );
  });

  it("calls an upheld dispute an unlearn", () => {
    expect(syncItemKind(event({ type: "dispute_upheld" }))).toBe("unlearn");
  });

  it("calls everything else about an entry an entry", () => {
    expect(syncItemKind(event({ type: "entry_submitted" }))).toBe("entry");
    expect(syncItemKind(event({ type: "validation" }))).toBe("entry");
    expect(syncItemKind(event({ type: "reconfirmation" }))).toBe("entry");
  });
});

describe("keepSyncItem", () => {
  it("drops a superseded entry when flattening, and keeps the rest", () => {
    const flat = query({ flatten: true });
    expect(keepSyncItem("entry", state("superseded"), flat)).toBe(false);
    expect(keepSyncItem("entry", state("verified"), flat)).toBe(true);
    expect(keepSyncItem("entry", state("draft"), flat)).toBe(true);
    // Without flatten the chain is delivered whole.
    expect(keepSyncItem("entry", state("superseded"), query())).toBe(true);
  });

  it("drops anything the demanded tier does not cover", () => {
    const observed = query({ min_tier: "observed" });
    const stated = query({ min_tier: "stated" });

    expect(keepSyncItem("entry", state("draft"), observed)).toBe(false);
    expect(keepSyncItem("entry", state("verified", "stated"), observed)).toBe(
      false,
    );
    expect(keepSyncItem("entry", state("verified", "observed"), stated)).toBe(
      true,
    );
    // A null effective tier promises nothing, so it satisfies nothing.
    expect(keepSyncItem("entry", state("verified", null), stated)).toBe(false);
    // With no demand at all, a draft is still part of the log.
    expect(keepSyncItem("entry", state("draft"), query())).toBe(true);
  });

  it("never withholds an unlearn or an event, whatever was asked for", () => {
    const strict = query({ flatten: true, min_tier: "observed" });
    for (const kind of ["unlearn", "event"] as const) {
      expect(keepSyncItem(kind, null, strict)).toBe(true);
      expect(keepSyncItem(kind, state("overturned", null), strict)).toBe(true);
      expect(keepSyncItem(kind, null, query())).toBe(true);
    }
  });

  it("throws on an entry item with no derived state", () => {
    expect(() => keepSyncItem("entry", null, query())).toThrow(
      /no derived state/,
    );
  });
});

describe("syncReceiptEntries", () => {
  const item = (
    kind: "entry" | "unlearn" | "event",
    id: string | null,
    status: SyncReceiptEntry["status"] | null = "verified",
  ) => ({
    kind,
    entry_id: id,
    entry_hash: id === null ? null : `sha256:${id.slice(-1).repeat(64)}`,
    status,
  });

  it("names each entry once, in first-delivery order", () => {
    const entries = syncReceiptEntries([
      item("entry", "nmk_b"),
      item("event", null, null),
      item("entry", "nmk_a", "draft"),
      // The same entry touched again by a later event in the same page.
      item("entry", "nmk_b"),
      item("unlearn", "nmk_c", "overturned"),
    ]);
    expect(entries.map((entry) => entry.entry_id)).toEqual([
      "nmk_b",
      "nmk_a",
      "nmk_c",
    ]);
    expect(entries[0]).toEqual({
      entry_id: "nmk_b",
      entry_hash: `sha256:${"b".repeat(64)}`,
      status: "verified",
    });
    expect(entries[2]!.status).toBe("overturned");
  });

  it("covers nothing when the page delivered only events", () => {
    expect(syncReceiptEntries([item("event", null, null)])).toEqual([]);
    expect(syncReceiptEntries([])).toEqual([]);
  });

  it("throws when an entry item names no entry", () => {
    expect(() => syncReceiptEntries([item("entry", null, null)])).toThrow(
      /names no entry/,
    );
  });
});

/**
 * What the entries listing accepts, and the order it refuses in.
 *
 * The same posture the frozen reader takes (test/read.test.ts): the enums come
 * from the published schema and never from a list retyped in TypeScript, and a
 * query wrong in two ways is reported by its first fault so the refusal does not
 * depend on how the parser happens to be written.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { DEFAULT_DOMAIN } from "../src/policy.js";
import {
  ENTRIES_QUERY_PARAMETERS,
  ENTRIES_QUERY_REFUSALS,
  ENTRY_CATEGORIES,
  ENTRY_STATUSES,
  ENTRY_TIERS,
  parseEntriesQuery,
} from "../src/ui/query.js";

const schema = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../schema/nomankind-entry-schema.json", import.meta.url)),
    "utf8",
  ),
) as {
  properties: {
    category: { enum: string[] };
    status: { enum: string[] };
    evidence_tier: { enum: string[] };
  };
};

const parse = (query: string) => parseEntriesQuery(new URLSearchParams(query));

describe("the accepted values come from the schema", () => {
  it("takes the category enum from the schema and nowhere else", () => {
    expect([...ENTRY_CATEGORIES]).toEqual(schema.properties.category.enum);
  });

  it("takes the status and tier enums from the schema too", () => {
    expect([...ENTRY_STATUSES]).toEqual(schema.properties.status.enum);
    expect([...ENTRY_TIERS]).toEqual(schema.properties.evidence_tier.enum);
  });

  it("accepts exactly six parameters", () => {
    expect([...ENTRIES_QUERY_PARAMETERS]).toEqual([
      "category",
      "status",
      "domain",
      "tier",
      "fresh",
      "before",
    ]);
  });

  it("names its refusals in the order it checks them", () => {
    expect([...ENTRIES_QUERY_REFUSALS]).toEqual([
      "unknown_parameter",
      "repeated_parameter",
      "bad_category",
      "bad_status",
      "unknown_domain",
      "bad_tier",
      "bad_fresh",
      "bad_before",
    ]);
  });
});

describe("what parses", () => {
  it("takes the empty query as no filter at all", () => {
    expect(parse("")).toEqual({
      ok: true,
      filter: {
        category: null,
        status: null,
        domain: null,
        tier: null,
        fresh: null,
      },
      before: null,
    });
  });

  it("parses a full query", () => {
    expect(
      parse(
        `category=pricing&status=verified&domain=${DEFAULT_DOMAIN}&tier=observed&fresh=stale&before=48213`,
      ),
    ).toEqual({
      ok: true,
      filter: {
        category: "pricing",
        status: "verified",
        domain: DEFAULT_DOMAIN,
        tier: "observed",
        fresh: "stale",
      },
      before: 48213,
    });
  });

  it("parses before as an integer, and accepts position zero", () => {
    const first = parse("before=7");
    expect(first.ok && first.before).toBe(7);
    const zero = parse("before=0");
    expect(zero.ok && zero.before).toBe(0);
  });

  it("accepts every value the schema publishes", () => {
    for (const category of ENTRY_CATEGORIES) {
      expect(parse(`category=${category}`).ok).toBe(true);
    }
    for (const status of ENTRY_STATUSES) {
      expect(parse(`status=${status}`).ok).toBe(true);
    }
    for (const tier of ENTRY_TIERS) {
      expect(parse(`tier=${tier}`).ok).toBe(true);
    }
    for (const fresh of ["fresh", "stale"]) {
      expect(parse(`fresh=${fresh}`).ok).toBe(true);
    }
  });
});

describe("what is refused, and by which parameter", () => {
  const cases: ReadonlyArray<readonly [string, string]> = [
    // An unknown parameter first: a reader who mistyped it would otherwise get
    // the unfiltered list back and believe they had filtered it.
    ["catagory=pricing", "unknown_parameter"],
    ["subject=openai/gpt-5", "unknown_parameter"],
    ["category=pricing&category=limit", "repeated_parameter"],
    ["before=1&before=2", "repeated_parameter"],
    ["category=prices", "bad_category"],
    // An empty value is a refusal, not an absence.
    ["category=", "bad_category"],
    ["status=pending", "bad_status"],
    ["status=", "bad_status"],
    ["tier=inferred", "bad_tier"],
    ["tier=", "bad_tier"],
    ["fresh=all", "bad_fresh"],
    ["fresh=", "bad_fresh"],
    ["before=-1", "bad_before"],
    ["before=1.5", "bad_before"],
    ["before=head", "bad_before"],
    ["before=", "bad_before"],
    ["before=99999999999999999999", "bad_before"],
  ];

  for (const [query, reason] of cases) {
    it(`refuses ?${query} as ${reason}`, () => {
      expect(parse(query)).toEqual({ ok: false, reason });
    });
  }

  it("reports the first fault when a query is wrong twice", () => {
    // Both parameters are bad; the check order decides which is reported.
    expect(parse("category=prices&status=pending")).toEqual({
      ok: false,
      reason: "bad_category",
    });
    expect(parse("nope=1&category=prices")).toEqual({
      ok: false,
      reason: "unknown_parameter",
    });
    expect(parse("status=pending&status=verified")).toEqual({
      ok: false,
      reason: "repeated_parameter",
    });
  });
});

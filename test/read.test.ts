/**
 * The frozen reader's query and choice (src/read.ts).
 *
 * Whitepaper Section 8, "The frozen reader": a reader asks for one fact and is
 * handed one entry. Everything here is a rule, not a ranking — the query is
 * refused rather than repaired, and an entry that fails any gate is not served
 * at all. So each test edits exactly one thing and watches the verdict.
 */

import { describe, expect, it } from "vitest";

import {
  READ_QUERY_REFUSALS,
  chooseReadable,
  isReadable,
  parseReadQuery,
  tierSatisfies,
  withinMaxAge,
  type Entry,
  type EvidenceTier,
  type ReadCandidate,
  type ReadQuery,
  type Sidecar,
} from "../src/index.js";

import { DEFAULT_DOMAIN } from "../src/policy.js";

const ENTRY_ID = "nmk_0123456789abcdef0123456789abcdef";

function query(search: string): ReturnType<typeof parseReadQuery> {
  return parseReadQuery(new URLSearchParams(search));
}

function refusal(search: string): string {
  const result = query(search);
  expect(result.ok).toBe(false);
  return (result as { ok: false; reason: string }).reason;
}

function accepted(search: string): ReadQuery {
  const result = query(search);
  expect(result).toMatchObject({ ok: true });
  return (result as { ok: true; query: ReadQuery }).query;
}

describe("parseReadQuery", () => {
  it("reads a query naming one entry", () => {
    expect(accepted(`entry_id=${ENTRY_ID}`)).toEqual({
      by: "entry",
      entry_id: ENTRY_ID,
    });
  });

  it("reads a subject query, with and without the optional demands", () => {
    expect(accepted("subject=openai/gpt-5&category=pricing")).toEqual({
      by: "subject",
      subject: "openai/gpt-5",
      category: "pricing",
    });
    expect(
      accepted(
        "subject=openai/gpt-5&category=pricing&min_tier=observed&max_age=30",
      ),
    ).toEqual({
      by: "subject",
      subject: "openai/gpt-5",
      category: "pricing",
      min_tier: "observed",
      max_age: 30,
    });
    expect(accepted("subject=x&category=behavior&max_age=0")).toMatchObject({
      max_age: 0,
    });
  });

  it("accepts every category and tier the schema publishes", () => {
    for (const category of [
      "release",
      "deprecation",
      "pricing",
      "limit",
      "behavior",
      "outage",
      "misbehavior",
      "correction",
    ]) {
      expect(accepted(`subject=x&category=${category}`)).toMatchObject({
        category,
      });
    }
    for (const tier of ["stated", "observed"]) {
      expect(
        accepted(`subject=x&category=pricing&min_tier=${tier}`),
      ).toMatchObject({ min_tier: tier });
    }
  });

  it("names its nine refusals in the order it checks them", () => {
    expect(READ_QUERY_REFUSALS).toEqual([
      "unknown_parameter",
      "bad_entry_id",
      "mixed_query",
      "missing_subject",
      "missing_category",
      "bad_category",
      "unknown_domain",
      "bad_min_tier",
      "bad_max_age",
    ]);
  });

  it("takes a domain, and refuses one the schema does not register", () => {
    const asked = accepted(
      `subject=openai/gpt-5&category=pricing&domain=${DEFAULT_DOMAIN}`,
    );
    expect(asked.by === "subject" && asked.domain).toBe(DEFAULT_DOMAIN);

    for (const bad of ["", "biotech", "Ai-Ecosystem"]) {
      expect(refusal(`subject=openai/gpt-5&category=pricing&domain=${bad}`)).toBe(
        "unknown_domain",
      );
    }
    // After bad_category, before bad_min_tier: the first fault wins.
    expect(refusal("subject=s&category=nope&domain=biotech")).toBe(
      "bad_category",
    );
    expect(
      refusal("subject=s&category=pricing&domain=biotech&min_tier=gold"),
    ).toBe("unknown_domain");
  });

  it("refuses an unknown parameter before anything else", () => {
    expect(refusal("sort=newest")).toBe("unknown_parameter");
    // A misspelt demand must never be silently ignored: the reader who wrote
    // min_teir asked for evidence and would be handed an answer that did not
    // have it.
    expect(refusal("subject=x&category=pricing&min_teir=observed")).toBe(
      "unknown_parameter",
    );
    // Checked first, so it wins over an entry_id that is also malformed.
    expect(refusal("entry_id=nope&sort=newest")).toBe("unknown_parameter");
  });

  it("refuses a malformed entry_id, before it notices the query is mixed", () => {
    for (const id of [
      "nope",
      "nmk_",
      "nmk_0123456789ABCDEF0123456789abcdef",
      `${ENTRY_ID}0`,
      ENTRY_ID.slice(0, -1),
      "01234567890123456789012345678901",
    ]) {
      expect(refusal(`entry_id=${id}`)).toBe("bad_entry_id");
    }
    expect(refusal("entry_id=nope&subject=x")).toBe("bad_entry_id");
  });

  it("refuses an entry_id mixed with any other parameter", () => {
    expect(refusal(`entry_id=${ENTRY_ID}&subject=x`)).toBe("mixed_query");
    expect(refusal(`entry_id=${ENTRY_ID}&max_age=30`)).toBe("mixed_query");
  });

  it("refuses a missing subject", () => {
    expect(refusal("")).toBe("missing_subject");
    expect(refusal("category=pricing")).toBe("missing_subject");
    expect(refusal("subject=&category=pricing")).toBe("missing_subject");
  });

  it("refuses a missing category, once the subject is there", () => {
    expect(refusal("subject=openai/gpt-5")).toBe("missing_category");
    expect(refusal("subject=openai/gpt-5&category=")).toBe("missing_category");
  });

  it("refuses a category outside the schema's enum", () => {
    expect(refusal("subject=x&category=fact")).toBe("bad_category");
    expect(refusal("subject=x&category=Pricing")).toBe("bad_category");
  });

  it("refuses a min_tier outside the schema's enum", () => {
    expect(refusal("subject=x&category=pricing&min_tier=measured")).toBe(
      "bad_min_tier",
    );
    expect(refusal("subject=x&category=pricing&min_tier=")).toBe("bad_min_tier");
  });

  it("refuses a max_age that is not a non-negative decimal integer", () => {
    for (const age of ["-1", "1.5", "30d", "", " 30", "0x1e", "1e3", "030"]) {
      expect(refusal(`subject=x&category=pricing&max_age=${age}`)).toBe(
        "bad_max_age",
      );
    }
  });
});

describe("tierSatisfies", () => {
  const table: [EvidenceTier | null, EvidenceTier | undefined, boolean][] = [
    // No demand: anything satisfies, null included — verification is the
    // status gate's question, not this one's.
    ["observed", undefined, true],
    ["stated", undefined, true],
    [null, undefined, true],
    // Observed is the stronger tier, so it satisfies either demand.
    ["observed", "observed", true],
    ["observed", "stated", true],
    // Stated cannot answer a demand for a measurement.
    ["stated", "observed", false],
    ["stated", "stated", true],
    // Null promises nothing, so it fails whenever a demand is made.
    [null, "observed", false],
    [null, "stated", false],
  ];

  for (const [effective, min, expected] of table) {
    it(`${String(effective)} against min_tier ${String(min)} is ${expected}`, () => {
      expect(tierSatisfies(effective, min)).toBe(expected);
    });
  }
});

describe("withinMaxAge", () => {
  const now = new Date("2026-09-09T12:00:00.000Z");

  it("is true when the reader made no age demand", () => {
    expect(withinMaxAge("2001-01-01", now, undefined)).toBe(true);
  });

  it("includes an entry confirmed exactly max_age days ago", () => {
    expect(withinMaxAge("2026-08-10", now, 30)).toBe(true);
  });

  it("excludes an entry confirmed one day older than that", () => {
    expect(withinMaxAge("2026-08-09", now, 30)).toBe(false);
  });

  it("includes anything confirmed inside the window, today included", () => {
    expect(withinMaxAge("2026-08-11", now, 30)).toBe(true);
    expect(withinMaxAge("2026-09-09", now, 30)).toBe(true);
  });

  it("takes max_age 0 as today only", () => {
    expect(withinMaxAge("2026-09-09", now, 0)).toBe(true);
    expect(withinMaxAge("2026-09-08", now, 0)).toBe(false);
  });

  it("counts calendar days, so the hour of the read does not move the bound", () => {
    const early = new Date("2026-09-09T00:00:00.000Z");
    const late = new Date("2026-09-09T23:59:59.999Z");
    expect(withinMaxAge("2026-08-10", early, 30)).toBe(true);
    expect(withinMaxAge("2026-08-10", late, 30)).toBe(true);
    expect(withinMaxAge("2026-08-09", late, 30)).toBe(false);
  });

  it("crosses a month and a leap day without drifting", () => {
    const march = new Date("2028-03-01T06:00:00.000Z");
    expect(withinMaxAge("2028-02-29", march, 1)).toBe(true);
    expect(withinMaxAge("2028-02-28", march, 1)).toBe(false);
    expect(withinMaxAge("2028-02-28", march, 2)).toBe(true);
  });

  it("takes a demand reaching back to the epoch as no demand at all", () => {
    // Every date the schema accepts is on or after 1970-01-01, so a window that
    // reaches the epoch cannot exclude anything.
    const daysSinceEpoch = Math.floor(now.getTime() / 86_400_000);
    expect(withinMaxAge("2001-01-01", now, daysSinceEpoch)).toBe(true);
    expect(withinMaxAge("1970-01-01", now, daysSinceEpoch)).toBe(true);
    expect(withinMaxAge("2001-01-01", now, daysSinceEpoch - 1)).toBe(true);
  });

  it("answers an absurd demand rather than throwing on it", () => {
    // The parser accepts any non-negative safe integer, and a cutoff instant
    // that far back is outside what a Date can hold. Counting in whole days
    // keeps it a question with an answer.
    for (const age of [
      Number.MAX_SAFE_INTEGER,
      Number.MAX_SAFE_INTEGER - 1,
      99_999_999_999,
      1_000_000_000,
    ]) {
      expect([age, withinMaxAge("2026-09-09", now, age)]).toEqual([age, true]);
      expect([age, withinMaxAge("2001-01-01", now, age)]).toEqual([age, true]);
    }
  });
});

describe("isReadable", () => {
  it("serves verified and nothing else", () => {
    expect(isReadable("verified")).toBe(true);
    for (const status of [
      "draft",
      "rejected",
      "superseded",
      "overturned",
      "",
    ]) {
      expect(isReadable(status)).toBe(false);
    }
  });
});

/** A candidate shaped only where the choice reads it. */
function candidate(
  id: string,
  status: string,
  lastConfirmed: string,
  effectiveTier: EvidenceTier | null,
): ReadCandidate {
  return {
    entry: {
      id,
      status,
      last_confirmed: lastConfirmed,
    } as unknown as Entry,
    sidecar: { effective_tier: effectiveTier } as unknown as Sidecar,
  };
}

describe("chooseReadable", () => {
  const now = new Date("2026-09-09T12:00:00.000Z");

  const bare: ReadQuery = { by: "subject", subject: "x", category: "pricing" };

  it("takes the first candidate, the caller having sorted newest first", () => {
    const newest = candidate("nmk_new", "verified", "2026-09-08", "observed");
    const older = candidate("nmk_old", "verified", "2026-09-01", "observed");
    expect(chooseReadable([newest, older], bare, now)).toBe(newest);
  });

  it("skips everything that is not verified", () => {
    const verified = candidate("nmk_ok", "verified", "2026-09-01", "stated");
    const chosen = chooseReadable(
      [
        candidate("nmk_draft", "draft", "2026-09-08", "observed"),
        candidate("nmk_super", "superseded", "2026-09-07", "observed"),
        candidate("nmk_over", "overturned", "2026-09-06", "observed"),
        candidate("nmk_rej", "rejected", "2026-09-05", "observed"),
        verified,
      ],
      bare,
      now,
    );
    expect(chosen).toBe(verified);
  });

  it("skips a verified entry whose effective tier is below the demand", () => {
    const stated = candidate("nmk_stated", "verified", "2026-09-08", "stated");
    const observed = candidate(
      "nmk_observed",
      "verified",
      "2026-09-01",
      "observed",
    );
    const demand: ReadQuery = { ...bare, min_tier: "observed" };
    expect(chooseReadable([stated, observed], demand, now)).toBe(observed);
    // With no demand the newest wins, tier and all.
    expect(chooseReadable([stated, observed], bare, now)).toBe(stated);
  });

  it("skips a verified entry that is older than the age demand", () => {
    const old = candidate("nmk_old", "verified", "2026-08-09", "observed");
    const fresh = candidate("nmk_fresh", "verified", "2026-08-10", "observed");
    const demand: ReadQuery = { ...bare, max_age: 30 };
    expect(chooseReadable([old, fresh], demand, now)).toBe(fresh);
  });

  it("answers null rather than the best of a bad set", () => {
    const demand: ReadQuery = { ...bare, min_tier: "observed", max_age: 30 };
    expect(
      chooseReadable(
        [
          candidate("nmk_draft", "draft", "2026-09-08", "observed"),
          candidate("nmk_weak", "verified", "2026-09-08", "stated"),
          candidate("nmk_stale", "verified", "2026-01-01", "observed"),
          candidate("nmk_null", "verified", "2026-09-08", null),
        ],
        demand,
        now,
      ),
    ).toBeNull();
    expect(chooseReadable([], demand, now)).toBeNull();
  });

  it("makes no tier or age demand of a query that named one entry", () => {
    const stated = candidate("nmk_stated", "verified", "2001-01-01", "stated");
    const byEntry: ReadQuery = { by: "entry", entry_id: ENTRY_ID };
    expect(chooseReadable([stated], byEntry, now)).toBe(stated);
  });
});

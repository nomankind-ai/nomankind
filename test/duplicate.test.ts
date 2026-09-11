/**
 * The duplicate rule, at the kernel (decision D-085).
 *
 * The same fact filed twice is refused at the door, and what "the same fact"
 * means is exactly four things: the domain, the subject, the category, and the
 * `after` value normalized under step 4 of norm-v1.2. Everything below is that
 * sentence, read once from each side.
 *
 * Pure: no database, no clock, no keys. The cores here are literals rather than
 * signed cores, because `checkDuplicate` reads five of the eighteen keys and
 * never verifies a signature — what is under test is the rule, not the seal.
 */

import { describe, expect, it } from "vitest";

import { CORE_KEYS, type Core } from "../src/core.js";
import {
  DUPLICATE_REFUSALS,
  LIVE_STATUSES,
  checkDuplicate,
  duplicateKey,
  type DuplicateCandidate,
} from "../src/duplicate.js";
import { DEFAULT_DOMAIN } from "../src/policy.js";

/** A core with every key the schema names, and nothing invented. */
function core(overrides: Partial<Record<string, unknown>> = {}): Core {
  const built: Record<string, unknown> = {};
  for (const key of CORE_KEYS) built[key] = null;
  return {
    ...built,
    id: "nmk_00000000000000000000000000000001",
    subject: "example/kestrel-2",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Kestrel-2 seat pricing rose to $25 per seat per month",
    before: "$20 per seat per month",
    after: "$25 per seat per month",
    effective_at: "2026-09-01",
    evidence_tier: "document",
    citation: "https://kestrel.example/pricing",
    snapshot_hash: `sha256:${"0".repeat(64)}`,
    norm_version: "norm-v1.2",
    supersedes: null,
    author: `1F916_${"a".repeat(32)}`,
    author_operator: null,
    submitted_at: "2026-09-08T12:00:00.000Z",
    ...overrides,
  } as Core;
}

/** One candidate row, as the submit door builds it out of a stored entry. */
function candidate(
  id: string,
  status: string,
  overrides: Partial<Record<string, unknown>> = {},
): DuplicateCandidate {
  return { id, status, core: core({ id, ...overrides }) };
}

describe("the key of a claim", () => {
  it("is the domain, the subject, the category and the normalized value", () => {
    expect(duplicateKey(core())).toEqual({
      domain: DEFAULT_DOMAIN,
      subject: "example/kestrel-2",
      category: "pricing",
      value: "$25 per seat per month",
    });
  });

  it("normalizes the value, so whitespace does not buy a second copy", () => {
    // Step 4 of norm-v1.2: CRLF to LF, runs of spaces and tabs collapsed,
    // each line trimmed, the document trimmed.
    const spaced = core({ after: "  $25   per\tseat\r\nper month  " });
    expect(duplicateKey(spaced).value).toBe("$25 per seat\nper month");
    expect(duplicateKey(core({ after: "$25 per seat per month" })).value).toBe(
      "$25 per seat per month",
    );
    expect(
      duplicateKey(core({ after: "$25 per seat per month   " })).value,
    ).toBe(duplicateKey(core()).value);
  });

  it("does not fold case: normalization is not a judgment about meaning", () => {
    // norm-v1.2 step 4 has no case rule, and inventing one here would make the
    // door decide that two differently written claims mean the same thing.
    // That judgment is the validators', under the published rejection form.
    expect(duplicateKey(core({ after: "$25 Per Seat Per Month" })).value).not.toBe(
      duplicateKey(core()).value,
    );
  });
});

describe("checking a new claim against what is already filed", () => {
  const filed = candidate("nmk_000000000000000000000000000000a1", "draft");
  const fresh = core({ id: "nmk_000000000000000000000000000000b1" });

  it("accepts when nothing is filed", () => {
    expect(checkDuplicate(fresh, [])).toEqual({ ok: true });
  });

  it("refuses a claim already held by a live entry, naming it", () => {
    expect(checkDuplicate(fresh, [filed])).toEqual({
      ok: false,
      reason: "duplicate_claim",
      duplicate_of: filed.id,
    });
    expect(DUPLICATE_REFUSALS).toContain("duplicate_claim");
  });

  it("refuses one whose value differs only by whitespace", () => {
    const spaced = core({
      id: fresh["id"],
      after: "$25   per seat per month\n",
    });
    expect(checkDuplicate(spaced, [filed])).toEqual({
      ok: false,
      reason: "duplicate_claim",
      duplicate_of: filed.id,
    });
  });

  it("accepts when the domain, subject, category or value differs", () => {
    const others: DuplicateCandidate[] = [
      candidate("nmk_000000000000000000000000000000c1", "draft", {
        domain: "biosecurity",
      }),
      candidate("nmk_000000000000000000000000000000c2", "draft", {
        subject: "example/kestrel-3",
      }),
      candidate("nmk_000000000000000000000000000000c3", "draft", {
        category: "limits",
      }),
      candidate("nmk_000000000000000000000000000000c4", "draft", {
        after: "$26 per seat per month",
      }),
    ];
    for (const other of others) {
      expect(checkDuplicate(fresh, [other])).toEqual({ ok: true });
    }
    // And all four together are still four different claims.
    expect(checkDuplicate(fresh, others)).toEqual({ ok: true });
  });

  it("refuses against a verified entry as readily as against a draft", () => {
    const verified = candidate(
      "nmk_000000000000000000000000000000d1",
      "verified",
    );
    expect(LIVE_STATUSES).toEqual(["draft", "verified"]);
    expect(checkDuplicate(fresh, [verified])).toEqual({
      ok: false,
      reason: "duplicate_claim",
      duplicate_of: verified.id,
    });
  });

  it("ignores rejected, superseded and overturned entries: a fact may be refiled", () => {
    for (const status of ["rejected", "superseded", "overturned"]) {
      const dead = candidate(
        "nmk_000000000000000000000000000000e1",
        status,
      );
      expect(checkDuplicate(fresh, [dead])).toEqual({ ok: true });
    }
  });

  it("ignores an unknown status rather than treating it as live", () => {
    const odd = candidate("nmk_000000000000000000000000000000e2", "stale");
    expect(checkDuplicate(fresh, [odd])).toEqual({ ok: true });
  });

  it("lets a superseding entry refile the claim it names", () => {
    const superseder = core({
      id: fresh["id"],
      supersedes: filed.id,
    });
    expect(checkDuplicate(superseder, [filed])).toEqual({ ok: true });
  });

  it("still refuses a superseder that duplicates some other live entry", () => {
    const other = candidate("nmk_000000000000000000000000000000f1", "verified");
    const superseder = core({ id: fresh["id"], supersedes: filed.id });
    expect(checkDuplicate(superseder, [other, filed])).toEqual({
      ok: false,
      reason: "duplicate_claim",
      duplicate_of: other.id,
    });
  });

  it("is not a duplicate of itself", () => {
    const self = candidate(fresh["id"] as string, "draft");
    expect(checkDuplicate(fresh, [self])).toEqual({ ok: true });
  });

  it("names the newest live candidate, not the oldest", () => {
    // The door passes them newest submission first, as readCandidates does.
    const newest = candidate("nmk_00000000000000000000000000000a02", "verified");
    const oldest = candidate("nmk_00000000000000000000000000000a01", "draft");
    expect(checkDuplicate(fresh, [newest, oldest])).toEqual({
      ok: false,
      reason: "duplicate_claim",
      duplicate_of: newest.id,
    });
  });

  it("skips a newer dead candidate to name the newest live one", () => {
    const dead = candidate("nmk_00000000000000000000000000000b03", "rejected");
    const live = candidate("nmk_00000000000000000000000000000b02", "draft");
    expect(checkDuplicate(fresh, [dead, live])).toEqual({
      ok: false,
      reason: "duplicate_claim",
      duplicate_of: live.id,
    });
  });

  /**
   * The dispute door hands its correction entry to `prepareSubmission`, so a
   * second correction asserting what an open correction of the same subject
   * already asserts meets this same rule. It is pinned here rather than end to
   * end: reaching it through the door needs two separately verified targets,
   * because a second challenge against one target is refused `dispute_open`
   * before a duplicate could be seen (test/m20-end-to-end.test.ts).
   */
  it("refuses a second correction duplicating an open one", () => {
    const open = candidate("nmk_00000000000000000000000000000c01", "draft", {
      category: "correction",
      after: "$44 per seat per month",
    });
    const second = core({
      id: "nmk_00000000000000000000000000000c02",
      category: "correction",
      after: "$44 per seat per month",
    });
    expect(checkDuplicate(second, [open])).toEqual({
      ok: false,
      reason: "duplicate_claim",
      duplicate_of: open.id,
    });
  });

  it("never throws on a core whose fields are not strings", () => {
    const odd = core({ id: fresh["id"], after: 25, subject: "example/x" });
    expect(() => checkDuplicate(odd, [filed])).not.toThrow();
    expect(checkDuplicate(odd, [filed])).toEqual({ ok: true });
    const twin = candidate("nmk_00000000000000000000000000000d01", "draft", {
      after: 25,
      subject: "example/x",
    });
    expect(checkDuplicate(odd, [twin])).toEqual({
      ok: false,
      reason: "duplicate_claim",
      duplicate_of: twin.id,
    });
  });
});

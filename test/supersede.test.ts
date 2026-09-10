/**
 * The supersession link check: same subject, same category, and nothing about
 * the attribute, which is the validators' judgment and not a string comparison.
 */

import { describe, expect, it } from "vitest";

import { DEFAULT_DOMAIN } from "../src/policy.js";

import { CORE_KEYS, type Core } from "../src/core.js";
import {
  checkSupersedes,
  SUPERSESSION_REFUSALS,
  type SupersessionRefusal,
} from "../src/supersede.js";

const OLD_ID = "nmk_01OLDENTRY";
const NEW_ID = "nmk_01NEWENTRY";
const CITATION = "https://platform.openai.com/docs/pricing";
const HASH = `sha256:${"a".repeat(64)}`;

/** A stated pricing core: the eighteen keys, exactly as the schema names them. */
function core(overrides: Record<string, unknown> = {}): Core {
  return {
    id: OLD_ID,
    subject: "openai/gpt-5",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "gpt-5 input price is $2.50 per million tokens",
    before: "$3.00",
    after: "$2.50",
    effective_at: "2026-08-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: CITATION,
    snapshot_hash: HASH,
    norm_version: "norm-v1.1",
    supersedes: null,
    author: "1F916:c3VwZXJzZWRlQXV0aG9y",
    author_operator: "op_brightloop",
    submitted_at: "2026-09-01T14:05:00Z",
    ...overrides,
  } as Core;
}

const target = core();

/** A lookup that knows one entry, and nothing else. */
const known = (entryId: string): Core | null =>
  entryId === OLD_ID ? target : null;

/** A lookup that knows nothing at all. */
const empty = (): Core | null => null;

function refusalOf(newCore: Core, lookup = known): SupersessionRefusal | null {
  const verdict = checkSupersedes(newCore, lookup);
  return verdict.ok ? null : verdict.reason;
}

describe("the cores the cases run on", () => {
  it("hold exactly the schema's core keys", () => {
    expect(Object.keys(core()).sort()).toEqual([...CORE_KEYS].sort());
  });
});

describe("checkSupersedes", () => {
  it("accepts a null link, naming no target", () => {
    const verdict = checkSupersedes(core({ id: NEW_ID }), known);
    expect(verdict).toEqual({ ok: true, target: null });
  });

  it("accepts a matching target, returning the target core", () => {
    const verdict = checkSupersedes(
      core({ id: NEW_ID, supersedes: OLD_ID, after: "$2.00" }),
      known,
    );
    expect(verdict).toEqual({ ok: true, target });
    if (verdict.ok) expect(verdict.target).toBe(target);
  });

  it("refuses an entry that supersedes itself", () => {
    expect(refusalOf(core({ id: OLD_ID, supersedes: OLD_ID }))).toBe(
      "self_supersession",
    );
  });

  it("refuses a target the lookup does not know", () => {
    expect(
      refusalOf(core({ id: NEW_ID, supersedes: OLD_ID }), empty),
    ).toBe("target_missing");
  });

  it("refuses a target with a different subject", () => {
    expect(
      refusalOf(
        core({ id: NEW_ID, supersedes: OLD_ID, subject: "anthropic/claude-4" }),
      ),
    ).toBe("subject_mismatch");
  });

  it("refuses a target with a different category", () => {
    expect(
      refusalOf(core({ id: NEW_ID, supersedes: OLD_ID, category: "limit" })),
    ).toBe("category_mismatch");
  });

  it("asks the lookup for the named target, once", () => {
    const asked: string[] = [];
    checkSupersedes(core({ id: NEW_ID, supersedes: OLD_ID }), (entryId) => {
      asked.push(entryId);
      return known(entryId);
    });
    expect(asked).toEqual([OLD_ID]);
  });

  it("says nothing about the attribute: a different claim still matches", () => {
    // "the price of the same thing" is the validators' judgment, recorded by
    // their approvals; the link check must not pretend to make it.
    const verdict = checkSupersedes(
      core({
        id: NEW_ID,
        supersedes: OLD_ID,
        claim: "gpt-5 output price is $10.00 per million tokens",
      }),
      known,
    );
    expect(verdict.ok).toBe(true);
  });

  it("says nothing about the target's own status", () => {
    // The target here is a plain core; nothing about draft, stale, or already
    // superseded reaches this check at all.
    expect(refusalOf(core({ id: NEW_ID, supersedes: OLD_ID }))).toBeNull();
  });
});

describe("SUPERSESSION_REFUSALS", () => {
  it("lists every refusal in check order", () => {
    expect(SUPERSESSION_REFUSALS).toEqual([
      "self_supersession",
      "target_missing",
      "subject_mismatch",
      "category_mismatch",
    ]);
  });

  it("is frozen", () => {
    expect(Object.isFrozen(SUPERSESSION_REFUSALS)).toBe(true);
  });

  it("takes the first refusal when several rules fail", () => {
    // Self-supersession beats a missing target: the id is checked before the
    // lookup is asked at all.
    expect(
      refusalOf(core({ id: OLD_ID, supersedes: OLD_ID }), empty),
    ).toBe("self_supersession");

    // A missing target beats a subject mismatch: there is nothing to compare.
    expect(
      refusalOf(
        core({ id: NEW_ID, supersedes: OLD_ID, subject: "anthropic/claude-4" }),
        empty,
      ),
    ).toBe("target_missing");

    // A subject mismatch beats a category mismatch.
    expect(
      refusalOf(
        core({
          id: NEW_ID,
          supersedes: OLD_ID,
          subject: "anthropic/claude-4",
          category: "limit",
        }),
      ),
    ).toBe("subject_mismatch");
  });
});

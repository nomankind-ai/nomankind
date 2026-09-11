/**
 * The published form a validator rejects a duplicate in (D-085).
 *
 * The form is the whole contract: nothing new is signed, the validate door takes
 * the string as it takes any other reason, and what makes it readable is that
 * `duplicate_claim:<entry id>` parses the same way everywhere. So these tests
 * pin the prefix verbatim, pin that a reason which nearly holds the form parses
 * as nothing, and pin that only a rejection can carry the claim.
 */

import { describe, expect, it } from "vitest";

import {
  DUPLICATE_REASON_PREFIX,
  duplicateOf,
  duplicateRejections,
  parseDuplicateReason,
} from "../src/duplicate-reason.js";

const ONE = "nmk_00112233445566778899aabbccddeeff";
const TWO = "nmk_ffeeddccbbaa99887766554433221100";

function approver(
  decision: "approve" | "reject",
  reason: unknown,
): Record<string, unknown> {
  return {
    agent: "1F916:k1",
    operator: "k1.example",
    decision,
    reason,
    snapshot_hash: `sha256:${"2".repeat(64)}`,
    assigned_random: false,
    test_accepted: null,
    reproduction: null,
    observation: null,
    signed_at: "2026-09-11T00:00:00.000Z",
  };
}

describe("the published duplicate reason", () => {
  it("is exactly the prefix the doors and the docs name", () => {
    expect(DUPLICATE_REASON_PREFIX).toBe("duplicate_claim:");
  });

  it("reads the entry id out of a well-formed reason", () => {
    expect(parseDuplicateReason(`${DUPLICATE_REASON_PREFIX}${ONE}`)).toBe(ONE);
  });

  it("parses nothing out of a reason whose id is not one", () => {
    // A form that nearly holds is not the form: the id becomes a link on the
    // entry page, and a truncated, uppercased or trailing-text id would be a
    // link to something the log does not hold.
    for (const bad of [
      `${DUPLICATE_REASON_PREFIX}nmk_00112233`,
      `${DUPLICATE_REASON_PREFIX}${ONE.toUpperCase()}`,
      `${DUPLICATE_REASON_PREFIX}${ONE}extra`,
      `${DUPLICATE_REASON_PREFIX}${ONE} `,
      `${DUPLICATE_REASON_PREFIX}${ONE},${TWO}`,
      `${DUPLICATE_REASON_PREFIX}00112233445566778899aabbccddeeff`,
      DUPLICATE_REASON_PREFIX,
      `duplicate_claim ${ONE}`,
      `the same fact as ${DUPLICATE_REASON_PREFIX}${ONE}`,
      "citation did not say it",
    ]) {
      expect([bad, parseDuplicateReason(bad)]).toEqual([bad, null]);
    }
  });

  it("parses nothing out of a reason that is not a string", () => {
    // The schema's `reason` is nullable and a stored row may hold anything at
    // all, so this answers rather than throws.
    for (const bad of [null, undefined, 7, true, {}, [ONE]]) {
      expect(parseDuplicateReason(bad)).toBeNull();
    }
  });
});

describe("what an entry's decisions say about duplication", () => {
  it("names the first rejection that carries the form", () => {
    const entry = {
      approvers: [
        approver("reject", "citation did not say it"),
        approver("reject", `${DUPLICATE_REASON_PREFIX}${ONE}`),
        approver("reject", `${DUPLICATE_REASON_PREFIX}${TWO}`),
      ],
    };
    expect(duplicateOf(entry)).toBe(ONE);
    expect(duplicateRejections(entry)).toBe(2);
  });

  it("ignores an approval that carries the form", () => {
    // An approval says the entry stands. Reading a duplicate claim out of it
    // would turn a vote for the entry into a mark against it.
    const entry = {
      approvers: [
        approver("approve", `${DUPLICATE_REASON_PREFIX}${ONE}`),
        approver("reject", `${DUPLICATE_REASON_PREFIX}${TWO}`),
      ],
    };
    expect(duplicateOf(entry)).toBe(TWO);
    expect(duplicateRejections(entry)).toBe(1);
  });

  it("says nothing about an entry nobody rejected as a duplicate", () => {
    const entry = { approvers: [approver("reject", "citation did not say it")] };
    expect(duplicateOf(entry)).toBeNull();
    expect(duplicateRejections(entry)).toBe(0);
  });

  it("reads an entry with no decisions, and one with no approvers key at all", () => {
    for (const entry of [{ approvers: [] }, {}, { approvers: null }, null]) {
      expect(duplicateOf(entry)).toBeNull();
      expect(duplicateRejections(entry)).toBe(0);
    }
  });
});

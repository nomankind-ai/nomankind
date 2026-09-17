/**
 * Attribution: who an entry is owed to, and the line a reader pastes.
 *
 * Decision D-127 names what a contributor is paid in now that the record is
 * free — "attribution on every read, cite the validator" — and decision D-130
 * makes the names an asset rather than a courtesy. This is the block those two
 * sentences describe, folded from one entry's own events.
 *
 * Both kinds of operator on the one surface (D-138): a `validation` from a
 * domain operator and a `community_validation` from a community one are the
 * same fact here, and `kind` is what says which. A draft says draft rather than
 * counting validators nobody has yet, and a reconfirmed entry names the
 * reconfirmer beside the validators.
 *
 * Pure: no Worker, no database, no clock.
 */

import { describe, expect, it } from "vitest";

import { attributionOf } from "../src/attribution.js";
import type { Core } from "../src/core.js";
import { appendEvent, type Event, type EventInput } from "../src/events.js";
import { DEFAULT_DOMAIN, NORM_VERSION, type OperatorKind } from "../src/policy.js";

const ENTRY_ID = "entry-1";
const AUTHOR = "1F916:author";

/** The entry as the record serves it, at the status under test. */
function entryAt(
  status: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: ENTRY_ID,
    subject: "example/kestrel-1",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Kestrel-1 seat pricing is $40 per seat per month",
    author: AUTHOR,
    author_operator: "author.example",
    status,
    seal: {
      log: "1F916",
      inclusion_proof: "proof",
      position: 17,
      sealed_at: "2026-09-08T12:05:00.000Z",
    },
    ...extra,
  };
}

/** The kinds map as `operatorKindsAt` would answer it at this position. */
const KINDS: ReadonlyMap<string, OperatorKind> = new Map<string, OperatorKind>([
  ["author.example", "domain"],
  ["k1.example", "domain"],
  ["k2.example", "domain"],
  ["k3.example", "domain"],
  ["reddit:checker", "community"],
]);

/** One entry's events, built by the real kernel so the fold reads real ones. */
async function log(inputs: readonly EventInput[]): Promise<Event[]> {
  let events: Event[] = [];
  for (const input of inputs) events = await appendEvent(events, input);
  return events;
}

function submitted(): EventInput {
  return {
    at: "2026-09-08T12:00:00.000Z",
    type: "entry_submitted",
    entry_id: ENTRY_ID,
    payload: {
      core: {
        id: ENTRY_ID,
        subject: "example/kestrel-1",
        category: "pricing",
        domain: DEFAULT_DOMAIN,
        claim: "Kestrel-1 seat pricing is $40 per seat per month",
        before: "$30 per seat per month",
        after: "$40 per seat per month",
        effective_at: "2026-09-01",
        evidence_tier: "stated",
        evidence: null,
        observation: null,
        citation: "https://example.test/pricing",
        snapshot_hash: `sha256:${"0".repeat(64)}`,
        norm_version: NORM_VERSION,
        supersedes: null,
        author: AUTHOR,
        author_operator: "author.example",
        submitted_at: "2026-09-08T12:00:00.000Z",
      } as Core,
      signature: "x",
    },
  };
}

function validation(
  operator: string,
  agent: string,
  at: string,
  options: {
    readonly decision?: "approve" | "reject";
    readonly assigned?: boolean;
  } = {},
): EventInput {
  return {
    at,
    type: "validation",
    entry_id: ENTRY_ID,
    payload: {
      record: {
        agent,
        operator,
        decision: options.decision ?? "approve",
        assigned_random: options.assigned ?? false,
        signed_at: at,
      },
      signature: "x",
    },
  };
}

function communityValidation(at: string): EventInput {
  return {
    at,
    type: "community_validation",
    entry_id: ENTRY_ID,
    payload: {
      entry_id: ENTRY_ID,
      operator: "reddit:checker",
      venue: "reddit",
      handle: "checker",
      agent: "1F916:community",
      decision: "approve",
      check: { kind: "span", value: "present" },
      reason: null,
      attestation_version: "nomankind-independence-v1",
      fingerprint: `sha256:${"1".repeat(64)}`,
      binding_proof: { kind: "profile", url: "https://reddit.test/u/checker" },
      comment_id: 12,
      line: 1,
      posted_at: at,
    } as never,
  };
}

describe("a verified entry", () => {
  it("names the author, every validator and which of them was drawn", async () => {
    const events = await log([
      submitted(),
      validation("k1.example", "1F916:k1", "2026-09-08T13:00:00.000Z"),
      validation("k2.example", "1F916:k2", "2026-09-08T13:10:00.000Z", {
        assigned: true,
      }),
      communityValidation("2026-09-08T13:20:00.000Z"),
    ]);

    const block = attributionOf(entryAt("verified"), events, KINDS);

    expect(block.author).toEqual({
      agent: AUTHOR,
      operator: "author.example",
    });
    expect(block.validators).toEqual([
      {
        agent: "1F916:k1",
        operator: "k1.example",
        kind: "domain",
        decision: "approve",
        assigned_random: false,
      },
      {
        agent: "1F916:k2",
        operator: "k2.example",
        kind: "domain",
        decision: "approve",
        assigned_random: true,
      },
      // The third path in (D-138), on the same surface and named as what it is:
      // nobody drew it, because it was said in public.
      {
        agent: "1F916:community",
        operator: "reddit:checker",
        kind: "community",
        decision: "approve",
        assigned_random: false,
      },
    ]);
    expect(block.reconfirmers).toEqual([]);

    // One line a reader pastes: the subject, the category, who verified it, the
    // entry and the sealed position it can be found at.
    expect(block.citation).toBe(
      "example/kestrel-1 pricing, verified by 3 validators " +
        "(k1.example, k2.example, reddit:checker), " +
        `nomankind entry ${ENTRY_ID}, seal position 17`,
    );
  });

  it("counts the operators that approved, and not the ones that argued against", async () => {
    const events = await log([
      submitted(),
      validation("k1.example", "1F916:k1", "2026-09-08T13:00:00.000Z"),
      validation("k3.example", "1F916:k3", "2026-09-08T13:30:00.000Z", {
        decision: "reject",
      }),
    ]);
    const block = attributionOf(entryAt("verified"), events, KINDS);

    // A rejection is in the block — it is part of who decided the entry — and
    // is not in the count of who verified it.
    expect(block.validators.map((row) => row.decision)).toEqual([
      "approve",
      "reject",
    ]);
    expect(block.citation).toContain("verified by 1 validator (k1.example)");
    expect(block.citation).not.toContain("k3.example");
  });

  it("labels a community validation as one even where the kinds are unknown", async () => {
    // A bounded bundle carries the entry's own events without the registry's,
    // so the map knows nobody: the event still says which kind it is.
    const events = await log([submitted(), communityValidation("2026-09-08T13:20:00.000Z")]);
    const block = attributionOf(entryAt("verified"), events, new Map());
    expect(block.validators[0]).toMatchObject({
      operator: "reddit:checker",
      kind: "community",
    });
  });
});

describe("a draft", () => {
  it("says draft rather than counting validators nobody has yet", async () => {
    const events = await log([submitted()]);
    const block = attributionOf(
      entryAt("draft", { seal: null }),
      events,
      KINDS,
    );
    expect(block.validators).toEqual([]);
    expect(block.citation).toBe(
      `example/kestrel-1 pricing, draft, nomankind entry ${ENTRY_ID}`,
    );
  });

  it("says draft even where a validator has already spoken", async () => {
    const events = await log([
      submitted(),
      validation("k1.example", "1F916:k1", "2026-09-08T13:00:00.000Z"),
    ]);
    const block = attributionOf(entryAt("draft"), events, KINDS);
    expect(block.validators.length).toBe(1);
    // One approval is not a consensus, and the line does not say it is.
    expect(block.citation).toContain(", draft, ");
    expect(block.citation).not.toContain("verified by");
  });
});

describe("a reconfirmed entry", () => {
  it("names the reconfirmer, and when the check was signed", async () => {
    const events = await log([
      submitted(),
      validation("k1.example", "1F916:k1", "2026-09-08T13:00:00.000Z"),
      {
        at: "2026-09-12T09:00:00.000Z",
        type: "reconfirmation",
        entry_id: ENTRY_ID,
        payload: {
          record: {
            agent: "1F916:k3",
            operator: "k3.example",
            snapshot_hash: `sha256:${"2".repeat(64)}`,
            reproduction: null,
            observation: null,
            signed_at: "2026-09-12T09:00:00.000Z",
          },
          signature: "x",
        },
      },
    ]);

    const block = attributionOf(entryAt("verified"), events, KINDS);
    expect(block.reconfirmers).toEqual([
      {
        agent: "1F916:k3",
        operator: "k3.example",
        kind: "domain",
        at: "2026-09-12T09:00:00.000Z",
      },
    ]);
    // A reconfirmation is a dated layer on top and never a second verification,
    // so the count in the line is unchanged.
    expect(block.citation).toContain("verified by 1 validator (k1.example)");
  });
});

describe("the events it is handed", () => {
  it("ignores another entry's events, so a whole log answers the same", async () => {
    const own = await log([
      submitted(),
      validation("k1.example", "1F916:k1", "2026-09-08T13:00:00.000Z"),
    ]);
    const others = await appendEvent(own, {
      at: "2026-09-08T14:00:00.000Z",
      type: "validation",
      entry_id: "another-entry",
      payload: {
        record: {
          agent: "1F916:k2",
          operator: "k2.example",
          decision: "approve",
          assigned_random: false,
          signed_at: "2026-09-08T14:00:00.000Z",
        },
        signature: "x",
      },
    });

    expect(attributionOf(entryAt("verified"), others, KINDS)).toEqual(
      attributionOf(entryAt("verified"), own, KINDS),
    );
  });

  it("reads them in seq order however the caller handed them in", async () => {
    const events = await log([
      submitted(),
      validation("k1.example", "1F916:k1", "2026-09-08T13:00:00.000Z"),
      validation("k2.example", "1F916:k2", "2026-09-08T13:10:00.000Z"),
    ]);
    const shuffled = [...events].reverse();
    expect(
      attributionOf(entryAt("verified"), shuffled, KINDS).validators.map(
        (row) => row.operator,
      ),
    ).toEqual(["k1.example", "k2.example"]);
  });
});

describe("a bare key's entry", () => {
  it("says the author has no operator rather than inventing one", async () => {
    const events = await log([submitted()]);
    const block = attributionOf(
      { ...entryAt("draft"), author_operator: null },
      events,
      KINDS,
    );
    expect(block.author).toEqual({ agent: AUTHOR, operator: null });
  });
});

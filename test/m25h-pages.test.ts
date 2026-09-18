/**
 * Standing as an asset, on the pages (decision D-130, M25h).
 *
 * Every renderer in src/ui/pages/ is a pure function of a data object the route
 * gathered, so every case here hands one in by hand and reads the document back
 * without a Worker, a database or a clock. What is checked is the promises the
 * decision made, not the markup: the leaderboard is ordered by standing with
 * ties sharing a rank, the marks are counters and the Record names them in the
 * words the decision fixed, the tier says what it allows in the policy module's
 * own sentence, the attribution block names the validators and hands a reader a
 * citation line, and the policy and API pages publish the numbers and the doors.
 *
 * No number and no word of policy is written out in this file. Every value is
 * read from POLICY or from the two functions the modules publish — `tierOf` and
 * `tierAllows` — so a cap that moves by a later decision moves in this test with
 * it. A test holding its own copy of a published number is a second policy
 * module.
 */

import { describe, expect, it } from "vitest";

import { attributionOf } from "../src/attribution.js";
import { confidenceInputs } from "../src/confidence.js";
import type { Sidecar } from "../src/derive.js";
import { ledgerBalance } from "../src/ledger.js";
import { DEFAULT_DOMAIN, POLICY } from "../src/policy.js";
import type { Entry } from "../src/schema.js";
import { tierOf, type RecordMarks, type StandingCounts } from "../src/standing.js";
import { renderApi } from "../src/ui/pages/api.js";
import { renderEntry } from "../src/ui/pages/entry.js";
import { renderOperator } from "../src/ui/pages/operator.js";
import {
  rankOperators,
  renderOperators,
} from "../src/ui/pages/operators.js";
import { renderPolicy, tierAllows } from "../src/ui/pages/policy.js";
import type {
  EntryData,
  OperatorData,
  OperatorRow,
  PageContext,
} from "../src/ui/types.js";

const ctx: PageContext = {
  environment: "local",
  path: "/operators",
  origin: "https://app.nomankind.ai",
  canonical_origin: "https://app.nomankind.ai",
};

const ENTRY_ID = "nmk_00112233445566778899aabbccddeeff";
const CORRECTION_ID = "nmk_ffeeddccbbaa99887766554433221100";
const HASH =
  "sha256:1111111111111111111111111111111111111111111111111111111111111111";

const NO_COUNTS: StandingCounts = {
  validations_volunteered: 0,
  validations_assigned: 0,
  validations_reproduced: 0,
  attestations_scored: 0,
  submissions_verified: 0,
  disputes_upheld: 0,
  revalidations_changed: 0,
  overturned: 0,
  missed: 0,
  forfeits: 0,
};

const NO_MARKS: RecordMarks = {
  overturned: [],
  missed: [],
  failed_disputes: [],
};

function operatorRow(overrides: Partial<OperatorRow> = {}): OperatorRow {
  const standing = overrides.standing ?? { standing: 12, seq: 40 };
  return {
    id: "k1.example",
    kind: "domain",
    community: null,
    maintainer: false,
    provider: false,
    trusted: true,
    trustedSeq: 4,
    registeredSeq: 2,
    agents: 1,
    domainSlugs: [DEFAULT_DOMAIN],
    validations: 3,
    overturned: 0,
    standing,
    counts: NO_COUNTS,
    tier: tierOf(standing === null ? 0 : standing.standing, true),
    cosigners: 1,
    perimeter: null,
    ...overrides,
  };
}

/** One row at a named standing, ranked by the page and by nothing else. */
function at(id: string, standing: number | null): OperatorRow {
  const cached = standing === null ? null : { standing, seq: 61 };
  return operatorRow({
    id,
    standing: cached,
    tier: tierOf(standing ?? 0, true),
  });
}

describe("the leaderboard", () => {
  it("orders by standing, descending, whatever order the rows came in", () => {
    const ranked = rankOperators([
      at("low.example", 1),
      at("high.example", 30),
      at("middle.example", 12),
    ]);
    expect(ranked.map((each) => each.operator.id)).toEqual([
      "high.example",
      "middle.example",
      "low.example",
    ]);
    expect(ranked.map((each) => each.rank)).toEqual([1, 2, 3]);
  });

  it("gives tied operators the same rank, and the next one the place after both", () => {
    const ranked = rankOperators([
      at("a.example", 30),
      at("b.example", 12),
      at("c.example", 12),
      at("d.example", 4),
    ]);
    expect(ranked.map((each) => [each.operator.id, each.rank])).toEqual([
      ["a.example", 1],
      ["b.example", 2],
      ["c.example", 2],
      ["d.example", 4],
    ]);
  });

  it("puts an operator nothing has been computed for below every number", () => {
    // Not computed and computed to nothing are different facts: a row with no
    // standing is not a zero and must not be ranked as one.
    const ranked = rankOperators([
      at("nothing.example", null),
      at("zero.example", 0),
    ]);
    expect(ranked.map((each) => each.operator.id)).toEqual([
      "zero.example",
      "nothing.example",
    ]);
  });

  it("renders the rows in that order, with the rank column beside them", () => {
    const html = renderOperators(ctx, {
      rows: [at("low.example", 1), at("high.example", 30)],
      bareKeys: null,
    });
    expect(html).toContain("<th>rank</th>");
    expect(html).toContain("ranked by standing");
    expect(html.indexOf("high.example")).toBeLessThan(
      html.indexOf("low.example"),
    );
  });

  it("carries the work counts and the three marks as counters", () => {
    const html = renderOperators(ctx, {
      rows: [
        operatorRow({
          counts: {
            ...NO_COUNTS,
            validations_volunteered: 3,
            validations_assigned: 4,
            validations_reproduced: 2,
            overturned: 5,
            missed: 6,
            forfeits: 7,
          },
        }),
      ],
      bareKeys: null,
    });
    expect(html).toContain("<th>validations</th>");
    expect(html).toContain("<th>reproduced</th>");
    expect(html).toContain("<th>marks</th>");
    // Volunteered plus assigned, added by the page and by nothing else.
    expect(html).toContain(">7</td>");
    expect(html).toContain("overturned 5");
    expect(html).toContain("missed 6");
    expect(html).toContain("forfeits 7");
  });

  it("shows a dash, and never a zero, where the fold has never run", () => {
    const html = renderOperators(ctx, {
      rows: [operatorRow({ standing: null, counts: null })],
      bareKeys: null,
    });
    expect(html).toContain(`<td class="dim">—</td>`);
  });

  it("says in one sentence why no bare key is listed", () => {
    const html = renderOperators(ctx, {
      rows: [operatorRow()],
      bareKeys: null,
    });
    expect(html).toContain("Bare keys are not listed");
    expect(html).toContain("a bare key has no operator and so no");
  });

  it("lists bare keys under the key when the route has that reading", () => {
    const html = renderOperators(ctx, {
      rows: [operatorRow()],
      bareKeys: [{ agent: "1F916:loner", standing: 2, seq: 61 }],
    });
    expect(html).toContain("Bare keys");
    expect(html).toContain("1F916:loner");
  });

  it("says the one thing standing buys, and the one it does not", () => {
    const html = renderOperators(ctx, {
      rows: [operatorRow()],
      bareKeys: null,
    });
    expect(html).toContain("standing buys is rate and reach");
  });
});

const OPERATOR_ID = "k1.example";

function operatorData(overrides: Partial<OperatorData> = {}): OperatorData {
  return {
    row: operatorRow(),
    agents: ["1F916:k1"],
    domains: [{ domain: DEFAULT_DOMAIN, attestationVersion: "v1" }],
    attestation: null,
    namedBy: null,
    marks: NO_MARKS,
    validations: [],
    cosigners: [],
    ledger: [],
    balance: ledgerBalance([], "2026-09-20T06:00:00.000Z"),
    attestations: { asModel: [], asScorer: [] },
    ...overrides,
  };
}

describe("the Record on an operator's page", () => {
  const marked: RecordMarks = {
    overturned: [
      {
        entry_id: ENTRY_ID,
        role: "validator",
        agent: "1F916:k1",
        seq: 88,
        at: "2026-09-10T00:00:00.000Z",
        correction_entry_id: CORRECTION_ID,
      },
    ],
    missed: [
      {
        entry_id: ENTRY_ID,
        agent: "1F916:k1",
        seq: 90,
        at: "2026-09-11T00:00:00.000Z",
      },
    ],
    failed_disputes: [
      {
        correction_entry_id: CORRECTION_ID,
        seq: 92,
        at: "2026-09-12T00:00:00.000Z",
      },
    ],
  };

  it("names an overturned signature in the words the decision fixed", () => {
    const html = renderOperator(ctx, operatorData({ marks: marked }));
    expect(html).toContain(
      "This agent signed an entry that was later\n                            overturned.",
    );
    // The row is one line with somewhere to go on both ends: the entry, and the
    // correction that overturned it.
    expect(html).toContain(`<a href="/entries/${ENTRY_ID}"`);
    expect(html).toContain(`<a href="/entries/${CORRECTION_ID}"`);
    expect(html).toContain("validator");
  });

  it("names a missed assignment and a failed dispute", () => {
    const html = renderOperator(ctx, operatorData({ marks: marked }));
    expect(html).toContain("Missed assignments");
    expect(html).toContain("did not\n                            answer it");
    expect(html).toContain("Failed disputes");
    expect(html).toContain("filed a dispute that failed");
  });

  it("says a mark is derived, permanent and never edited", () => {
    const html = renderOperator(ctx, operatorData({ marks: marked }));
    expect(html).toContain("derived from sealed events, never edited");
    expect(html).toContain("A mark is\n      permanent");
  });

  it("reads an empty Record as one sentence", () => {
    const html = renderOperator(ctx, operatorData());
    expect(html).toContain("Nothing is on this operator's Record");
    expect(html).not.toContain("Missed assignments");
  });
});

describe("what a tier allows, on the operator page", () => {
  it("prints the policy module's own sentence for the tier the standing puts it at", () => {
    for (const tier of POLICY.TIERS) {
      const html = renderOperator(
        ctx,
        operatorData({ row: operatorRow({ tier }) }),
      );
      expect(html).toContain(tierAllows(tier));
      expect(html).toContain("what this standing allows");
    }
  });

  it("says the tier is recomputed and gates participation rather than truth", () => {
    const html = renderOperator(ctx, operatorData());
    expect(html).toContain("The tier is not stored");
    expect(html).toContain("Participation is gated by it and truth is not");
  });
});

describe("the certificate, the badge and the citizen record", () => {
  it("links the certificate door and shows the badge with a line to paste", () => {
    const html = renderOperator(ctx, operatorData());
    const path = `/operators/${encodeURIComponent(OPERATOR_ID)}`;
    expect(html).toContain(`href="${path}/certificate"`);
    expect(html).toContain(`src="${path}/badge.svg"`);
    expect(html).toContain(`${ctx.origin}${path}/badge.svg`);
    expect(html).toContain("npm run verify -- --certificate");
  });

  it("names a domain operator's keys without inventing a registry door for them", () => {
    const html = renderOperator(ctx, operatorData());
    expect(html).toContain("The registry lists citizens by handle");
    expect(html).toContain("1F916:k1");
  });

  it("links a community operator's citizen record by its handle", () => {
    const venue = POLICY.CONFIRMATION_VENUES[0]?.venue ?? "1f916";
    const html = renderOperator(
      ctx,
      operatorData({
        row: operatorRow({
          id: `${venue}:alice`,
          kind: "community",
          community: {
            venue,
            handle: "alice",
            agent: "1F916:community-key",
            binding: {
              kind: "registry",
              registry: POLICY.REGISTRY.origin,
              key_bind_event_id: 4242,
            },
          },
        }),
      }),
    );
    expect(html).toContain(`${POLICY.REGISTRY.origin}/api/record/alice`);
  });
});

// ---------------------------------------------------------------------------
// The entry page's attribution block
// ---------------------------------------------------------------------------

const sidecar: Sidecar = {
  confirmations: [],
  bootstrap: null,
  needs_replacement: false,
  effective_tier: "stated",
  test_verdict: null,
  trusted_count_at_decision: 3,
  read_share_slots: [],
  revalidations: [],
  source: { class: "other", matched_host: null, authority: null },
  verification_class: "registered",
  verification_communities: [],
  verification_single_venue: false,
  verification_binding: null,
  verification_layers: [],
};

const entryRecord: Record<string, unknown> = {
  id: ENTRY_ID,
  subject: "kestrel/kestrel-1",
  category: "behavior",
  domain: DEFAULT_DOMAIN,
  claim: "The model refuses this prompt",
  before: "the model answered",
  after: "the model refuses",
  effective_at: "2026-09-01",
  evidence_tier: "stated",
  evidence: null,
  observation: null,
  citation: "https://kestrel.example/transcript",
  snapshot_hash: HASH,
  norm_version: "norm-v1.2",
  supersedes: null,
  author: "1F916:author",
  author_operator: "k3.example",
  submitted_at: "2026-09-08T12:00:00.000Z",
  signature: "c2lnbmF0dXJl",
  approvers: [],
  reconfirmations: [],
  disputes: [],
  failure_reports: [],
  seal: { position: 12 },
  staleness_window_days: 30,
  verified_at: "2026-09-08T13:00:00.000Z",
  last_confirmed: "2026-09-08",
  expires_at: "2026-10-08",
  stale: false,
  superseded_by: null,
  overturned_by: null,
  status: "verified",
  confidence: null,
};

/** One sealed validation, the shape the fold reads it in. */
const validationEvent = {
  seq: 14,
  at: "2026-09-08T13:00:00.000Z",
  type: "validation",
  entry_id: ENTRY_ID,
  payload: {
    record: {
      agent: "1F916:k1",
      operator: OPERATOR_ID,
      decision: "approve",
      assigned_random: true,
      signed_at: "2026-09-08T13:00:00.000Z",
    },
  },
  hash: HASH,
  prev_hash: null,
} as unknown as EntryData["events"][number];

function entryData(): EntryData {
  const events = [validationEvent];
  return {
    entry: entryRecord,
    sidecar,
    position: 12,
    events,
    seal: null,
    attribution: attributionOf(
      entryRecord as unknown as Entry,
      events,
      new Map([[OPERATOR_ID, "domain"]]),
    ),
    approvers: [],
    reconfirmations: [],
    superseders: [],
    stalenessWindowDays: 30,
    ledger: [],
    readShares: [],
    disputeOf: null,
    confidenceInputs: confidenceInputs({
      entry: entryRecord as unknown as Entry,
      sidecar,
      now: "2026-09-20T06:00:00.000Z",
    }),
    statement: null,
    disclosure: null,
  };
}

describe("the attribution block on an entry", () => {
  it("names the author, its operator and every validator that decided it", () => {
    const data = entryData();
    const html = renderEntry(ctx, data);
    expect(html).toContain("who made this, on every read");
    expect(html).toContain(String(entryRecord["author"]));
    expect(html).toContain(String(entryRecord["author_operator"]));
    expect(html).toContain("1F916:k1");
    expect(html).toContain(
      `<a href="/operators/${encodeURIComponent(OPERATOR_ID)}">`,
    );
    // The kind and the decision travel with the validator, and the draw is said
    // in a word rather than as a boolean.
    expect(html).toContain("drawn");
  });

  it("prints the citation line the fold produced, under the caption that asks for it", () => {
    const data = entryData();
    const html = renderEntry(ctx, data);
    expect(html).toContain("cite the validator");
    expect(html).toContain(data.attribution.citation);
    expect(html).toContain("Cite the validators, not only the log");
  });
});

// ---------------------------------------------------------------------------
// The policy page and the API page
// ---------------------------------------------------------------------------

describe("the policy page", () => {
  const html = renderPolicy(ctx, POLICY);

  it("publishes the contribution table, from keyless to trusted", () => {
    expect(html).toContain("Contribution");
    for (const who of [
      "keyless",
      "free key",
      "registered operator · probation",
      "registered operator · established",
      "registered operator · senior",
      "trusted operator",
    ]) {
      expect(html).toContain(who);
    }
    expect(html).toContain(String(POLICY.FREE_READS_PER_DAY_GLOBAL));
    expect(html).toContain(String(POLICY.OPERATOR_READS_PER_DAY));
    for (const tier of Object.values(POLICY.RATE_TIERS)) {
      expect(html).toContain(String(tier.reads_per_day));
    }
    expect(html).toContain("never buys truth");
  });

  it("publishes the tiers, their thresholds and what each allows", () => {
    expect(html).toContain("Tiers");
    for (const tier of POLICY.TIERS) {
      expect(html).toContain(`TIERS.${tier}`);
      expect(html).toContain(tierAllows(tier));
    }
    expect(html).toContain("STANDING_TRUSTED_ENTRY");
    expect(html).toContain(String(POLICY.STANDING_TRUSTED_ENTRY));
    expect(html).toContain("STANDING_SENIOR");
    expect(html).toContain(String(POLICY.STANDING_SENIOR));
    expect(html).toContain("DOMAIN_EARLY_ACCESS_DAYS");
    expect(html).toContain(String(POLICY.DOMAIN_EARLY_ACCESS_DAYS));
  });

  it("carries the three write caps, from policy and never from here", () => {
    for (const cap of [
      POLICY.WRITES_PER_AGENT_PER_DAY_PROBATION,
      POLICY.WRITES_PER_AGENT_PER_DAY,
      POLICY.WRITES_PER_AGENT_PER_DAY_SENIOR,
    ]) {
      expect(html).toContain(String(cap));
    }
  });
});

describe("the API page", () => {
  const html = renderApi(ctx);

  it("names the certificate doors, the badge and the attribution door", () => {
    for (const path of [
      "/operators/{id}/certificate",
      "/agents/{agent}/certificate",
      "/operators/{id}/badge.svg",
      "/entries/{id}/attribution",
    ]) {
      expect(html).toContain(path);
    }
  });

  it("says the attribution travels in the sync state", () => {
    expect(html).toContain("attribution block beside the entry and the sidecar");
  });

  it("names the two refusals the tiers guard", () => {
    expect(html).toContain("insufficient_tier");
    expect(html).toContain("early_access");
  });

  it("gives the command that checks a certificate", () => {
    expect(html).toContain("npm run verify -- --certificate");
  });
});

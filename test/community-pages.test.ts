/**
 * The pages of the second operator kind (decision D-138).
 *
 * Every renderer in src/ui/pages/ is a pure function of a data object the route
 * gathered, so each one here is handed a shape built by hand and read back
 * without a Worker, a database or a clock — the same split test/ui-pages-app
 * holds, exercised on the fields D-138 added.
 *
 * Two promises are checked throughout. The class an entry discloses is the one
 * derivation sealed, printed in the record's own field names and in the words
 * the decision fixed, with a draft showing none at all. And no number and no
 * word of policy is written out in this file: the policy page's group is
 * checked against `POLICY` and against the two functions the module publishes,
 * so a value that moves by a later decision moves in the test with it — a test
 * holding its own copy of a published number is a second policy module.
 */

import { describe, expect, it } from "vitest";

import { attributionOf } from "../src/attribution.js";
import { confidenceInputs } from "../src/confidence.js";
import type { Sidecar } from "../src/derive.js";
import type { CommunityBinding } from "../src/events.js";
import { ledgerBalance } from "../src/ledger.js";
import {
  attestationFor,
  communityCapPerEntry,
  countingCommunities,
  DEFAULT_DOMAIN,
  POLICY,
  REGISTRY,
  VERIFICATION_CLASSES,
} from "../src/policy.js";
import { communityOperatorId } from "../src/registry.js";
import { tierOf } from "../src/standing.js";
import type { Entry } from "../src/schema.js";
import { renderApi } from "../src/ui/pages/api.js";
import { renderEntries } from "../src/ui/pages/entries.js";
import {
  entryVerificationView,
  renderEntry,
} from "../src/ui/pages/entry.js";
import { renderOperator } from "../src/ui/pages/operator.js";
import { renderOperators } from "../src/ui/pages/operators.js";
import { renderPolicy } from "../src/ui/pages/policy.js";
import type {
  ApproverRow,
  EntryData,
  EntryRow,
  OperatorData,
  OperatorRow,
  PageContext,
} from "../src/ui/types.js";

const ctx: PageContext = {
  environment: "local",
  path: "/entries",
  origin: "https://app.nomankind.ai",
  canonical_origin: "https://app.nomankind.ai",
};

const ENTRY_ID = "nmk_00112233445566778899aabbccddeeff";
const HASH =
  "sha256:1111111111111111111111111111111111111111111111111111111111111111";

/** The one venue whose binding counts today, read from the policy module. */
const VENUE = countingCommunities()[0] ?? "1f916";
const HANDLE = "alice";
const COMMUNITY_ID = communityOperatorId(VENUE, HANDLE);

/** A sidecar with no class yet: the shape every fixture below starts from. */
const baseSidecar: Sidecar = {
  confirmations: [],
  bootstrap: null,
  needs_replacement: false,
  effective_tier: "stated",
  test_verdict: null,
  trusted_count_at_decision: 3,
  read_share_slots: [],
  revalidations: [],
  source: { class: "other", matched_host: null, authority: null },
  verification_class: null,
  verification_communities: [],
  verification_single_venue: false,
  verification_binding: null,
  verification_layers: [],
};

/** Domain operators alone met the consensus. */
const registeredSidecar: Sidecar = {
  ...baseSidecar,
  verification_class: "registered",
  verification_binding: null,
  verification_layers: [
    {
      kind: "decision",
      class: "registered",
      binding: "key",
      seq: 14,
      at: "2026-09-08T13:00:00.000Z",
      operator: null,
    },
  ],
};

/** Community operators alone met it, and all of them on one venue. */
const communitySidecar: Sidecar = {
  ...baseSidecar,
  verification_class: "community",
  verification_communities: [VENUE],
  verification_single_venue: true,
  verification_layers: [
    {
      kind: "decision",
      class: "community",
      binding: "key",
      seq: 14,
      at: "2026-09-08T13:00:00.000Z",
      operator: null,
    },
    {
      kind: "reconfirmation",
      class: "registered",
      binding: "key",
      seq: 41,
      at: "2026-09-14T09:00:00.000Z",
      operator: "k1.example",
    },
  ],
};

/** Both took part, and the consensus needed the community validators. */
const mixedSidecar: Sidecar = {
  ...baseSidecar,
  verification_class: "mixed",
  verification_communities: [VENUE],
  verification_single_venue: false,
  verification_layers: [
    {
      kind: "decision",
      class: "mixed",
      binding: "key",
      seq: 14,
      at: "2026-09-08T13:00:00.000Z",
      operator: null,
    },
  ],
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
  seal: null,
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

/** One community validator's decision, as the route joins it (D-138). */
const communityApprover: ApproverRow = {
  agent: "1F916:community-key",
  operator: COMMUNITY_ID,
  operatorKind: "community",
  community: { venue: VENUE, handle: HANDLE },
  operatorTrusted: false,
  decision: "approve",
  reason: null,
  snapshot_hash: HASH,
  assigned_random: false,
  test_accepted: null,
  reproduction: null,
  observation: null,
  signed_at: "2026-09-08T13:00:00.000Z",
  seq: 14,
};

const NOW = "2026-09-20T06:00:00.000Z";

function entryData(sidecar: Sidecar, status = "verified"): EntryData {
  const entry = { ...entryRecord, status };
  return {
    entry,
    sidecar,
    position: 12,
    events: [],
    seal: null,
    // The block the entry page renders (D-130), folded by the kernel over the
    // entry's own events exactly as the route folds it.
    attribution: attributionOf(entry as unknown as Entry, [], new Map()),
    approvers: [communityApprover],
    reconfirmations: [],
    superseders: [],
    stalenessWindowDays: 30,
    ledger: [],
    readShares: [],
    disputeOf: null,
    confidenceInputs: confidenceInputs({
      entry: entry as unknown as Entry,
      sidecar,
      now: NOW,
    }),
    statement: null,
    disclosure: null,
  };
}

describe("the entry page and its JSON view model", () => {
  it("says who met a mixed consensus", () => {
    const html = renderEntry(ctx, entryData(mixedSidecar));
    expect(html).toContain(
      "Verified by both, the consensus needing community validators",
    );
    expect(html).toContain("verification_class");
  });

  it("names the single venue a community consensus came from", () => {
    const html = renderEntry(ctx, entryData(communitySidecar));
    expect(html).toContain(
      `Verified by community validators (single venue: ${VENUE})`,
    );
    // The communities that validated it, and the later layer as a dated line.
    expect(html).toContain(VENUE);
    expect(html).toContain("reconfirmed by a registered validator at seal 41");
  });

  it("says a registered consensus in its own words", () => {
    const html = renderEntry(ctx, entryData(registeredSidecar));
    expect(html).toContain("Verified by registered validators");
    expect(html).not.toContain("Verified by community validators");
  });

  it("says a draft is awaiting validators rather than lacking a class", () => {
    const html = renderEntry(ctx, entryData(baseSidecar, "draft"));
    expect(html).not.toContain("Verified by registered validators");
    expect(html).not.toContain("Verified by community validators");
    // D-142: "no class" reads as a verdict where a draft is simply waiting.
    expect(html).toContain("Awaiting validators");
    expect(html).toContain("nothing has been decided about this entry yet");
  });

  it("shows a community validator with its kind, venue and handle", () => {
    const html = renderEntry(ctx, entryData(mixedSidecar));
    // Encoded, as every other operator link on the site is: a community id is
    // `<venue>:<handle>` (D-138) and a raw colon in a path is a link to
    // somewhere else.
    expect(html).toContain(
      `/operators/${encodeURIComponent(COMMUNITY_ID)}`,
    );
    expect(html).toContain(HANDLE);
    expect(html).toContain("community");
  });

  it("carries the five class fields in the sidecar's own names", () => {
    const view = entryVerificationView(communitySidecar);
    expect(view).toEqual({
      verification_class: communitySidecar.verification_class,
      verification_communities: communitySidecar.verification_communities,
      verification_single_venue: communitySidecar.verification_single_venue,
      // The rung joined them at D-142, and the view is still the sidecar's own
      // names carried verbatim: the page and the JSON door read one model.
      verification_binding: communitySidecar.verification_binding ?? null,
      verification_layers: communitySidecar.verification_layers,
    });
    expect(Object.keys(view)).toEqual([
      "verification_class",
      "verification_communities",
      "verification_single_venue",
      "verification_binding",
      "verification_layers",
    ]);
  });
});

function entryRow(
  id: string,
  verification_class: EntryRow["verification_class"],
): EntryRow {
  return {
    id,
    position: 12,
    sealed: true,
    status: verification_class === null ? "draft" : "verified",
    subject: "kestrel/kestrel-1",
    category: "behavior",
    domain: DEFAULT_DOMAIN,
    claim: "The model refuses this prompt",
    tier: "stated",
    verification_class,
    // A row the fixture says nothing about the rung of (D-142).
    verification_binding: null,
    last_confirmed: "2026-09-08",
    expires_at: "2026-10-08",
    stale: false,
  };
}

describe("the entries listing's class filter", () => {
  it("offers one chip per class, weakest first", () => {
    const html = renderEntries(ctx, {
      filter: {
        category: null,
        status: null,
        domain: null,
        source: null,
        tier: null,
        fresh: null,
        min_class: null,
        min_binding: null,
      },
      rows: [],
      total: 0,
      nextBefore: null,
    });
    expect(html).toContain("min_class");
    const positions = VERIFICATION_CLASSES.map((value) =>
      html.indexOf(`name="min_class" value="${value}"`),
    );
    for (const position of positions) expect(position).toBeGreaterThan(-1);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it("carries the asked class through every other chip's link", () => {
    const html = renderEntries(ctx, {
      filter: {
        category: null,
        status: null,
        domain: null,
        source: null,
        tier: null,
        fresh: null,
        min_class: "mixed",
        min_binding: null,
      },
      rows: [entryRow(ENTRY_ID, "mixed")],
      total: 1,
      nextBefore: null,
    });
    // Every "all" link but the class group's own keeps the class.
    expect(html).toContain("/entries?min_class=mixed");
    // And the class group's "all" is the one link that drops it.
    expect(html).toContain('href="/entries"');
    // The row prints the word.
    expect(html).toContain("<td class=\"muted\">mixed</td>");
  });

  it("prints no class word for an entry that has met no consensus", () => {
    const html = renderEntries(ctx, {
      filter: {
        category: null,
        status: null,
        domain: null,
        source: null,
        tier: null,
        fresh: null,
        min_class: null,
        min_binding: null,
      },
      rows: [entryRow(ENTRY_ID, null)],
      total: 1,
      nextBefore: null,
    });
    expect(html).not.toContain("<td class=\"muted\">registered</td>");
    expect(html).not.toContain("<td class=\"muted\">community</td>");
  });
});

const REGISTRY_BINDING: CommunityBinding = {
  kind: "registry",
  registry: REGISTRY.origin,
  key_bind_event_id: 4242,
};

function operatorRow(overrides: Partial<OperatorRow> = {}): OperatorRow {
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
    standing: { standing: 12, seq: 40 },
    counts: null,
    tier: tierOf(12, true),
    cosigners: 1,
    perimeter: "kestrel-labs",
    ...overrides,
  };
}

const communityRow: OperatorRow = operatorRow({
  id: COMMUNITY_ID,
  kind: "community",
  community: {
    venue: VENUE,
    handle: HANDLE,
    agent: "1F916:community-key",
    binding: REGISTRY_BINDING,
  },
  trusted: false,
  trustedSeq: null,
  perimeter: null,
});

describe("the operators directory", () => {
  it("has a kind column naming both kinds", () => {
    const html = renderOperators(ctx, {
      rows: [operatorRow(), communityRow],
      bareKeys: null,
    });
    expect(html).toContain("<th>kind</th>");
    for (const kind of POLICY.OPERATOR_KINDS) expect(html).toContain(kind);
    expect(html).toContain(HANDLE);
    expect(html).toContain("outside every perimeter");
  });
});

describe("a community operator's page", () => {
  const data: OperatorData = {
    row: communityRow,
    agents: ["1F916:community-key"],
    domains: [
      {
        domain: DEFAULT_DOMAIN,
        attestationVersion: attestationFor(DEFAULT_DOMAIN).version,
      },
    ],
    attestation: null,
    namedBy: null,
    // No upgrade off the account rung (D-142).
    bindings: [],
    validations: [
      {
        entryId: ENTRY_ID,
        decision: "approve",
        seq: 14,
        signed_at: "2026-09-08T13:00:00.000Z",
      },
    ],
    cosigners: [],
    ledger: [],
    balance: ledgerBalance([], NOW),
    attestations: { asModel: [], asScorer: [] },
    // Nothing is on this operator's Record, which the page says in a sentence.
    marks: { overturned: [], missed: [], failed_disputes: [] },
  };

  it("shows the account, the key, the binding and its reference", () => {
    const html = renderOperator(ctx, data);
    expect(html).toContain(VENUE);
    expect(html).toContain(HANDLE);
    expect(html).toContain("1F916:community-key");
    expect(html).toContain(REGISTRY_BINDING.kind);
    expect(html).toContain(`${REGISTRY.origin}/api/record/${HANDLE}`);
  });

  it("shows its domains, its validations and no perimeter", () => {
    const html = renderOperator(ctx, data);
    expect(html).toContain(DEFAULT_DOMAIN);
    expect(html).toContain(`/entries/${ENTRY_ID}`);
    expect(html).toContain("outside every perimeter");
  });
});

describe("the policy page's community group", () => {
  const html = renderPolicy(ctx, POLICY);
  const counting = countingCommunities();

  it("renders every published value of the group", () => {
    expect(html).toContain("Community operators");
    expect(html).toContain(POLICY.OPERATOR_KINDS.join(", "));
    expect(html).toContain(POLICY.BINDING_KINDS.join(", "));
    expect(html).toContain(POLICY.COUNTING_BINDING_KINDS.join(", "));
    expect(html).toContain(String(POLICY.COMMUNITY_MIN_ACCOUNTS));
    expect(html).toContain(String(POLICY.COMMUNITY_MIN_COMMUNITIES));
    expect(html).toContain(POLICY.VERIFICATION_CLASSES.join(", "));
    expect(html).toContain(
      `${POLICY.CONFIRMATION_ATTESTATION_TOKEN_PREFIX}&lt;version&gt;`,
    );
  });

  it("states the per-entry cap as the function of the counting communities", () => {
    expect(html).toContain(`communityCapPerEntry(${counting.length})`);
    expect(html).toContain(String(communityCapPerEntry(counting.length)));
    for (const venue of counting) expect(html).toContain(venue);
  });
});

describe("the API page", () => {
  const html = renderApi(ctx);

  it("documents min_class and its refusal", () => {
    expect(html).toContain("min_class");
    expect(html).toContain("bad_min_class");
    expect(html).toContain(POLICY.VERIFICATION_CLASSES.join("|"));
  });

  it("names the three community event types", () => {
    expect(html).toContain("community_operator_registered");
    expect(html).toContain("community_operator_joined_domain");
    expect(html).toContain("community_validation");
  });

  it("names the confirmation line's attestation token", () => {
    expect(html).toContain(
      `${POLICY.CONFIRMATION_ATTESTATION_TOKEN_PREFIX}&lt;version&gt;`,
    );
  });
});

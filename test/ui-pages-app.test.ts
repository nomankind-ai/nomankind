/**
 * The five app pages as pure functions.
 *
 * Every renderer in src/ui/pages/ is a function of a data object the route
 * gathered, so each one can be handed a shape built by hand and read back
 * without a Worker, a database or a clock. That is the point of the split, and
 * these tests are what hold it: nothing here opens a store.
 *
 * Two things are checked on every page. The fields a reader needs are present —
 * for the entry page that means every CORE_KEYS name and every derived field
 * name, because Whitepaper Section 3 says a reader has to be able to check the
 * entry offline and a field the page silently dropped is a field they cannot
 * check. And somebody else's text never becomes markup: the claim and the subject
 * below carry a script tag, and it has to come back escaped on every page that
 * shows them.
 */

import { describe, expect, it } from "vitest";

import { CORE_KEYS } from "../src/core.js";
import type { Sidecar } from "../src/derive.js";
import type { Event } from "../src/events.js";
import { TRUSTED_POOL_SWITCH } from "../src/policy.js";
import type { Seal } from "../src/seal.js";
import type { StakeRecord } from "../src/stake.js";
import { renderEntries } from "../src/ui/pages/entries.js";
import { renderEntry } from "../src/ui/pages/entry.js";
import { renderHome } from "../src/ui/pages/home.js";
import { renderOperator } from "../src/ui/pages/operator.js";
import { renderOperators } from "../src/ui/pages/operators.js";
import { shortHash } from "../src/ui/html.js";
import type {
  EntryData,
  EntryRow,
  OperatorRow,
  PageContext,
} from "../src/ui/types.js";

/** The payload a hostile submitter would put in a claim. */
const HOSTILE = `<script>alert(1)</script>`;

const ctx: PageContext = {
  environment: "local",
  path: "/entries",
  origin: "https://app.nomankind.ai",
};

const ENTRY_ID = "nmk_00112233445566778899aabbccddeeff";
const OTHER_ID = "nmk_ffeeddccbbaa99887766554433221100";
/** The correction filed against the entry, and the entry this one corrects. */
const CORRECTION_ID = "nmk_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";
const DISPUTED_ID = "nmk_a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";

const HASH =
  "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_HASH =
  "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const ARTIFACT_HASH =
  "sha256:3333333333333333333333333333333333333333333333333333333333333333";

const row: EntryRow = {
  id: ENTRY_ID,
  position: 12,
  sealed: true,
  status: "verified",
  subject: `kestrel/kestrel-1 ${HOSTILE}`,
  category: "behavior",
  claim: `The model refuses this prompt ${HOSTILE}`,
  tier: "stated",
  last_confirmed: "2026-09-08",
  expires_at: "2026-10-08",
  stale: true,
};

/** The same entry one seq later, still uncovered by any seal. */
const unsealedRow: EntryRow = {
  ...row,
  id: OTHER_ID,
  position: 13,
  sealed: false,
  status: "draft",
  claim: "The model may refuse this prompt",
  tier: null,
  stale: false,
};

const sidecar: Sidecar = {
  needs_replacement: false,
  effective_tier: "stated",
  test_verdict: "rejected",
  trusted_count_at_decision: 3,
  read_share_slots: [
    { operator: "k1.example", seq: 8 },
    { operator: "k2.example", seq: 9 },
  ],
  revalidations: [
    {
      request_seq: 31,
      requester: "1F916:k4",
      operator: "k4.example",
      source: "operator",
      requested_at: "2026-09-10T09:00:00.000Z",
      assigned: {
        agent: "1F916:k5",
        operator: "k5.example",
        deadline: "2026-09-11T09:00:00.000Z",
      },
      outcome: "held",
      resolved_at: "2026-09-10T18:00:00.000Z",
      checker: "1F916:k5",
      correction_entry_id: CORRECTION_ID,
    },
    {
      request_seq: 34,
      requester: null,
      operator: null,
      source: "failure_reports",
      requested_at: "2026-09-11T09:00:00.000Z",
      assigned: null,
      outcome: "open",
      resolved_at: null,
      checker: null,
      correction_entry_id: null,
    },
  ],
};

/** The stake rows the dispute above put on the ledger. */
const ledger: StakeRecord[] = [
  {
    kind: "dispute_stake",
    entry_id: ENTRY_ID,
    correction_entry_id: CORRECTION_ID,
    request_seq: null,
    agent: "1F916:k4",
    operator: "k4.example",
    unit: "standing",
    amount: 10,
    seq: 41,
    at: "2026-09-10T09:00:00.000Z",
  },
  {
    kind: "dispute_reward",
    entry_id: ENTRY_ID,
    correction_entry_id: CORRECTION_ID,
    request_seq: null,
    agent: "1F916:k4",
    operator: null,
    unit: null,
    amount: null,
    seq: 42,
    at: "2026-09-10T18:00:00.000Z",
  },
];

/** The whole entry record, with a derived half and a hostile claim. */
const entryRecord: Record<string, unknown> = {
  id: ENTRY_ID,
  subject: row.subject,
  category: "behavior",
  claim: row.claim,
  before: "the model answered",
  after: "the model refuses",
  effective_at: "2026-09-01",
  evidence_tier: "observed",
  evidence: {
    model: "kestrel-1",
    prompt: `say something ${HOSTILE}`,
    parameters: { temperature: 0 },
    output: "I cannot help with that.",
    predicate: "the model refuses this prompt",
    observed_at: "2026-09-01",
    provider_statement: null,
  },
  observation: null,
  citation: "https://kestrel.example/transcript",
  snapshot_hash: HASH,
  norm_version: "norm-v1.2",
  supersedes: OTHER_ID,
  author: "1F916:author",
  author_operator: "k3.example",
  submitted_at: "2026-09-08T12:00:00.000Z",
  signature: "c2lnbmF0dXJl",
  approvers: [
    {
      agent: "1F916:k1",
      operator: "k1.example",
      decision: "approve",
      reason: null,
      snapshot_hash: HASH,
      assigned_random: false,
      test_accepted: false,
      reproduction: {
        model: "kestrel-1",
        output: "I cannot help with that.",
        observed_at: "2026-09-08",
        runs: 10,
        holds: 9,
      },
      observation: null,
      signed_at: "2026-09-08T12:00:00.000Z",
    },
    {
      agent: "1F916:k2",
      operator: "k2.example",
      decision: "reject",
      reason: `the source says otherwise ${HOSTILE}`,
      snapshot_hash: OTHER_HASH,
      assigned_random: true,
      test_accepted: false,
      reproduction: null,
      observation: null,
      signed_at: "2026-09-08T13:00:00.000Z",
    },
  ],
  reconfirmations: [
    {
      agent: "1F916:k3",
      operator: "k3.example",
      snapshot_hash: OTHER_HASH,
      reproduction: null,
      observation: null,
      signed_at: "2026-09-09T12:00:00.000Z",
    },
  ],
  disputes: [
    {
      id: CORRECTION_ID,
      challenger: "1F916:k4",
      operator: "k4.example",
      citation: "https://kestrel.example/correction",
      snapshot_hash: OTHER_HASH,
      outcome: "upheld",
      reason: `the transcript was cut ${HOSTILE}`,
      filed_at: "2026-09-10T09:00:00.000Z",
      resolved_at: "2026-09-10T18:00:00.000Z",
    },
  ],
  failure_reports: [
    {
      reporter: "1F916:reader",
      operator: null,
      observed: `the model answered anyway ${HOSTILE}`,
      artifact_hash: ARTIFACT_HASH,
      citation: "https://kestrel.example/report",
      upgraded_to: CORRECTION_ID,
      filed_at: "2026-09-09T20:00:00.000Z",
    },
  ],
  seal: {
    log: "1F916",
    inclusion_proof: "inclusion-proof-string-0012",
    position: 12,
    witnesses: ["1F916:witness-one"],
    sealed_at: "2026-09-08T12:05:00.000Z",
  },
  staleness_window_days: 30,
  verified_at: "2026-09-08T13:00:00.000Z",
  last_confirmed: "2026-09-08",
  expires_at: "2026-10-08",
  stale: true,
  superseded_by: null,
  overturned_by: OTHER_ID,
  status: "verified",
  confidence: null,
};

const events: Event[] = [
  {
    seq: 12,
    at: "2026-09-08T12:00:00.000Z",
    type: "entry_submitted",
    entry_id: ENTRY_ID,
    payload: {
      core: {} as never,
      signature: "c2lnbmF0dXJl",
    },
    prev_hash: null,
    hash: OTHER_HASH,
  } as Event,
  {
    seq: 14,
    at: "2026-09-08T12:00:00.000Z",
    type: "validation",
    entry_id: ENTRY_ID,
    payload: {
      record: {
        agent: "1F916:k1",
        operator: "k1.example",
        decision: "approve",
        assigned_random: false,
        signed_at: "2026-09-08T12:00:00.000Z",
      },
      signature: "c2ln",
    },
    prev_hash: OTHER_HASH,
    hash: HASH,
  } as Event,
];

const seal: Seal = {
  seq: 3,
  first_seq: 10,
  last_seq: 20,
  size: 11,
  root: "sha256:root",
  sealed_at: "2026-09-08T12:05:00.000Z",
  prev_hash: null,
  hash: "sha256:sealhash",
  witnesses: [{ agent: "1F916:witness-one", signature: "c2ln" }],
  registry: null,
};

const entryData: EntryData = {
  entry: entryRecord,
  sidecar,
  position: 12,
  events,
  seal,
  approvers: [
    {
      agent: "1F916:k1",
      operator: "k1.example",
      operatorTrusted: true,
      decision: "approve",
      reason: null,
      snapshot_hash: HASH,
      assigned_random: false,
      test_accepted: false,
      reproduction: { runs: 10, holds: 9 },
      observation: null,
      signed_at: "2026-09-08T12:00:00.000Z",
      seq: 14,
    },
    {
      agent: "1F916:k2",
      operator: "k2.example",
      operatorTrusted: null,
      decision: "reject",
      reason: `the source says otherwise ${HOSTILE}`,
      snapshot_hash: OTHER_HASH,
      assigned_random: true,
      test_accepted: false,
      reproduction: null,
      observation: null,
      signed_at: "2026-09-08T13:00:00.000Z",
      seq: null,
    },
  ],
  reconfirmations: [
    {
      record: entryRecord["reconfirmations"] instanceof Array
        ? (entryRecord["reconfirmations"][0] as Record<string, unknown>)
        : {},
      seq: 17,
      operatorTrusted: false,
    },
  ],
  superseders: [OTHER_ID],
  stalenessWindowDays: 30,
  ledger,
  disputeOf: DISPUTED_ID,
};

const operatorRow: OperatorRow = {
  id: "k1.example",
  maintainer: false,
  provider: false,
  trusted: true,
  trustedSeq: 5,
  registeredSeq: 2,
  agents: 2,
  validations: 7,
  overturned: 2,
};

/** Every page, so the escaping check runs over all of them at once. */
function everyPage(): Record<string, string> {
  return {
    home: renderHome(ctx, {
      counters: {
        verified: 4,
        stale: 1,
        trusted: 3,
        sealedHead: 20,
        sealedAt: "2026-09-08T12:05:00.000Z",
        witnesses: 1,
        seals: 2,
      },
      latest: [row],
    }),
    entries: renderEntries(ctx, {
      filter: { category: null, status: "verified", tier: null, fresh: null },
      rows: [row],
      total: 9,
      nextBefore: 12,
    }),
    entry: renderEntry(ctx, entryData),
    operators: renderOperators(ctx, {
      rows: [operatorRow, { ...operatorRow, id: "maintainer.example", maintainer: true, trusted: false, trustedSeq: null }],
    }),
    operator: renderOperator(ctx, {
      row: operatorRow,
      agents: ["1F916:k1", "1F916:k1b"],
      attestation: {
        version: "nomankind-independence-v1",
        signed_at: "2026-08-01T00:00:00.000Z",
        signature: "YXR0ZXN0",
      },
      namedBy: "1F916:maintainer",
      payoutStatus: "onboarded",
      validations: [
        {
          entryId: ENTRY_ID,
          decision: "approve",
          seq: 14,
          signed_at: "2026-09-08T12:00:00.000Z",
        },
      ],
    }),
  };
}

describe("nobody else's text becomes markup", () => {
  it("escapes a script tag on every page that shows a claim, a subject or a reason", () => {
    for (const [name, document] of Object.entries(everyPage())) {
      expect([name, document.includes("<script")]).toEqual([name, false]);
      expect([name, document.includes("</script")]).toEqual([name, false]);
    }
    const shown = everyPage();
    for (const name of ["home", "entries", "entry"]) {
      expect([name, shown[name]!.includes("&lt;script&gt;alert(1)&lt;/script&gt;")]).toEqual([
        name,
        true,
      ]);
    }
  });
});

/** The pos cell of one row: the linked position, and any mark beside it. */
function positionCell(document: string, id: string): string {
  const pattern = new RegExp(
    `<a href="/entries/${id}">(\\d+)</a>([^<]*(?:<span[^>]*>[^<]*</span>)?)`,
  );
  const match = pattern.exec(document);
  if (match === null) return "";
  return `${match[1]}${match[2]}`.trim();
}

describe("the home page", () => {
  const document = renderHome(ctx, {
    counters: {
      verified: 4,
      stale: 2,
      trusted: 3,
      sealedHead: 20,
      sealedAt: "2026-09-08T12:05:00.000Z",
      witnesses: 1,
      seals: 2,
    },
    latest: [row, unsealedRow],
  });

  it("shows the four counters and what each one means", () => {
    for (const label of ["VERIFIED", "STALE", "TRUSTED POOL", "HEAD"]) {
      expect(document).toContain(label);
    }
    expect(document).toContain("bounty accruing");
    expect(document).toContain(`random draw active at ${TRUSTED_POOL_SWITCH}`);
    expect(document).toContain("sealed 2026-09-08 12:05:00Z · 1 witnesses");
  });

  it("names the three ways to read the log as they exist today", () => {
    expect(document).toContain(`GET ${ctx.origin}/read?subject=`);
    expect(document).toContain(`min_tier=observed`);
    expect(document).toContain(`GET ${ctx.origin}/sync?from=20`);
    expect(document).toContain("flatten=true");
    expect(document).toContain(`npm run export -- ${ctx.origin} ${ENTRY_ID} ./out`);
    expect(document).toContain(
      "npm run verify -- ./out/entry.json ./out/log.json",
    );
  });

  it("links every latest row to its entry", () => {
    expect(document).toContain(`href="/entries/${ENTRY_ID}"`);
  });

  it("marks the row no seal covers yet, and marks no other", () => {
    expect(positionCell(document, ENTRY_ID)).toBe(String(row.position));
    expect(positionCell(document, OTHER_ID)).toBe(
      `${unsealedRow.position} <span class="warn">unsealed</span>`,
    );
  });

  it("says so plainly when nothing has been sealed", () => {
    const empty = renderHome(ctx, {
      counters: {
        verified: 0,
        stale: 0,
        trusted: 0,
        sealedHead: null,
        sealedAt: null,
        witnesses: null,
        seals: 0,
      },
      latest: [],
    });
    expect(empty).toContain("no seal yet");
    expect(empty).toContain("Nothing has been submitted yet.");
    expect(empty).not.toContain("bounty accruing");
  });
});

describe("the entries listing", () => {
  const document = renderEntries(ctx, {
    filter: { category: "behavior", status: "verified", tier: null, fresh: "stale" },
    rows: [row, unsealedRow],
    total: 9,
    nextBefore: 12,
  });

  it("counts what it shows against the total, in sealed order", () => {
    expect(document).toContain("2 of 9 · ordered by sealed\n          position");
    expect(document).toContain("title=\"The total counts every entry with this status");
  });

  it("is one GET form of radio chips with the current filter checked", () => {
    expect(document).toContain('<form class="filters" method="get" action="/entries">');
    expect(document).toContain(
      '<input type="radio" name="category" value="behavior" checked />',
    );
    expect(document).toContain(
      '<input type="radio" name="status" value="verified" checked />',
    );
    expect(document).toContain(
      '<input type="radio" name="fresh" value="stale" checked />',
    );
    expect(document).toContain('type="submit">Apply</button>');
    // The unchecked ones are there and are not checked.
    expect(document).toContain('<input type="radio" name="tier" value="observed" />');
  });

  it("gives every group an all chip that drops only its own filter", () => {
    expect(document).toContain(
      'href="/entries?status=verified&amp;fresh=stale"',
    );
    expect(document).toContain(
      'href="/entries?category=behavior&amp;status=verified&amp;fresh=stale"',
    );
  });

  it("pages by sealed position, carrying the filter", () => {
    expect(document).toContain(
      'href="/entries?category=behavior&amp;status=verified&amp;fresh=stale&amp;before=12"',
    );
    expect(document).toContain(">Next page</a>");
  });

  it("says which position is sealed and which is not yet", () => {
    // EntryRow.sealed is computed from the stored entry's seal object, so the
    // listing shows it rather than leaving a reader to assume every position on
    // a page ordered by sealed position is itself sealed.
    expect(positionCell(document, ENTRY_ID)).toBe(String(row.position));
    expect(positionCell(document, OTHER_ID)).toBe(
      `${unsealedRow.position} <span class="warn">unsealed</span>`,
    );
  });

  it("refuses to pretend an empty page is a page", () => {
    const empty = renderEntries(ctx, {
      filter: { category: null, status: null, tier: null, fresh: null },
      rows: [],
      total: 0,
      nextBefore: null,
    });
    expect(empty).toContain("No entries match these filters.");
    expect(empty).not.toContain("Next page");
  });
});

/** The one value the seal block shows under `position`, or "" when it shows none. */
function sealPosition(document: string): string {
  const match = /<dt>position<\/dt>\s*<dd>([^<]*)<\/dd>/.exec(document);
  return match === null ? "" : match[1]!.trim();
}

describe("the entry page", () => {
  const document = renderEntry(ctx, entryData);

  it("shows every immutable core key, by the schema's own name", () => {
    for (const key of CORE_KEYS) {
      expect([key, document.includes(`<dt>${key}</dt>`)]).toEqual([key, true]);
    }
  });

  it("shows the value of every core field that has one", () => {
    for (const value of [
      ENTRY_ID,
      "the model answered",
      "the model refuses",
      "2026-09-01",
      "observed",
      "https://kestrel.example/transcript",
      HASH,
      "norm-v1.2",
      OTHER_ID,
      "1F916:author",
      "k3.example",
      "2026-09-08T12:00:00.000Z",
    ]) {
      expect([value, document.includes(value)]).toEqual([value, true]);
    }
    // The nested core objects are shown whole, as JSON.
    expect(document).toContain("&quot;predicate&quot;");
  });

  it("shows every derived field name and never a confidence number", () => {
    for (const key of [
      "status",
      "staleness_window_days",
      "verified_at",
      "last_confirmed",
      "expires_at",
      "stale",
      "superseded_by",
      "overturned_by",
      "confidence",
    ]) {
      expect([key, document.includes(`<dt>${key}</dt>`)]).toEqual([key, true]);
    }
    expect(document).toContain(`<span class="dim">null</span>`);
  });

  it("shows the effective tier as the tier and the claimed tier beside it", () => {
    expect(document).toContain("tier shown is the sidecar's effective_tier");
    expect(document).toContain("evidence_tier observed");
    expect(document).toContain(`<span class="badge ">stated</span>`);
  });

  it("says how old the confirmation is, and that the entry is stale", () => {
    expect(document).toContain("confirmed 2026-09-08, window 30 days, expires");
    expect(document).toContain(`<span class="warn">stale</span>`);
    // Section 7: a stale entry stays verified.
    expect(document).toContain(`<span class="badge s-verified">verified</span>`);
  });

  it("shows the sidecar the schema cannot hold", () => {
    for (const name of [
      "effective_tier",
      "test_verdict",
      "needs_replacement",
      "trusted_count_at_decision",
      "read_share_slots",
    ]) {
      expect([name, document.includes(`<dt>${name}</dt>`)]).toEqual([name, true]);
    }
    expect(document).toContain("k1.example · seq 8");
  });

  it("shows every decision, its operator's trust and its position in the log", () => {
    expect(document).toContain("1F916:k1");
    expect(document).toContain('<a href="/operators/k1.example">');
    expect(document).toContain(`<span class="accent">trusted</span>`);
    expect(document).toContain(`<span class="dim">unknown</span>`);
    expect(document).toContain("10·9");
    expect(document).toContain("the source says otherwise");
  });

  it("shows the seal, the proof, and the archive behind the hash", () => {
    expect(document).toContain("inclusion-proof-string-0012");
    expect(document).toContain("sha256:root");
    expect(document).toContain("1F916:witness-one");
    expect(document).toContain(`href="/captures/${HASH}"`);
    expect(document).toContain(`href="/captures/${HASH}/sidecar"`);
    expect(document).toContain(`href="/events/14/proof"`);
  });

  it("names the two commands that verify it offline", () => {
    expect(document).toContain(
      `npm run export -- ${ctx.origin} ${ENTRY_ID} ./out`,
    );
    expect(document).toContain(
      "npm run verify -- ./out/entry.json ./out/log.json",
    );
  });

  it("shows the seal object's own position, never the submitted seq", () => {
    // The stored seal object is the only thing that knows where the entry sits
    // in a seal. The submitted seq is a log position and not a seal position, so
    // a seal object that names none leaves the field empty rather than borrowing
    // it: `position: 12` below is the seal's, and `position` on the data is the
    // submission's, and the two are not the same fact.
    expect(sealPosition(document)).toBe("12");

    const moved = renderEntry(ctx, {
      ...entryData,
      position: 12,
      entry: {
        ...entryRecord,
        seal: { ...(entryRecord["seal"] as Record<string, unknown>), position: 99 },
      },
    });
    expect(sealPosition(moved)).toBe("99");

    const { position: _submitted, ...sealWithoutPosition } = entryRecord[
      "seal"
    ] as Record<string, unknown>;
    const nameless = renderEntry(ctx, {
      ...entryData,
      position: 12,
      entry: { ...entryRecord, seal: sealWithoutPosition },
    });
    expect(sealPosition(nameless)).toBe("—");
    expect(nameless).not.toContain("<dd>12</dd>");
  });

  it("says unsealed rather than inventing a seal", () => {
    const unsealed = renderEntry(ctx, {
      ...entryData,
      entry: { ...entryRecord, seal: null },
      seal: null,
    });
    expect(unsealed).toContain("unsealed");
    expect(unsealed).not.toContain("inclusion-proof-string-0012");
  });
});

/**
 * What was filed against the entry, beside what was signed for it (M20).
 *
 * The three arrays and the ledger rows are read straight off the data the route
 * gathered, so the assertions below are about the page and never about a
 * derivation: the outcomes, the links a reader follows to check a challenge, and
 * the escaping that has to survive a reporter who wrote a script tag into a
 * plain-language field.
 */
describe("the entry page's disputes, reports, revalidations and stakes", () => {
  const document = renderEntry(ctx, entryData);

  it("shows every field of a dispute, and links the challenge itself", () => {
    expect(document).toContain(">Disputes</h2>");
    expect(document).toContain(`<a href="/entries/${CORRECTION_ID}">`);
    expect(document).toContain("1F916:k4");
    expect(document).toContain('<a href="/operators/k4.example">');
    expect(document).toContain("https://kestrel.example/correction");
    expect(document).toContain(shortHash(OTHER_HASH));
    expect(document).toContain(`<span class="badge b-upheld">upheld</span>`);
    expect(document).toContain("the transcript was cut");
    expect(document).toContain("2026-09-10 09:00:00Z");
    expect(document).toContain("2026-09-10 18:00:00Z");
  });

  it("shows every field of a failure report, escaped, with its artifact", () => {
    expect(document).toContain(">Failure reports</h2>");
    expect(document).toContain("1F916:reader");
    // The reporter is a bare key: the page says so rather than showing nothing.
    expect(document).toContain(`<span class="dim">bare key</span>`);
    expect(document).toContain("the model answered anyway");
    expect(document).toContain(`href="/captures/${ARTIFACT_HASH}"`);
    expect(document).toContain("https://kestrel.example/report");
    expect(document).toContain("2026-09-09 20:00:00Z");
    // Somebody else's text in a plain-language field is text, never markup.
    expect(document).not.toContain("<script");
    expect(document).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("says which report was upgraded and which was not", () => {
    expect(document).toContain(`<a href="/entries/${CORRECTION_ID}">`);
    const notUpgraded = renderEntry(ctx, {
      ...entryData,
      entry: {
        ...entryRecord,
        failure_reports: [
          {
            reporter: "1F916:reader",
            operator: "k6.example",
            observed: "the model answered anyway",
            artifact_hash: ARTIFACT_HASH,
            citation: null,
            upgraded_to: null,
            filed_at: "2026-09-09T20:00:00.000Z",
          },
        ],
      },
    });
    expect(notUpgraded).toContain(`<span class="dim">not upgraded</span>`);
    expect(notUpgraded).toContain('<a href="/operators/k6.example">');
  });

  it("shows every field of a revalidation, from the sidecar", () => {
    expect(document).toContain(">Revalidations</h2>");
    expect(document).toContain("<td class=\"dim\">31</td>");
    expect(document).toContain('href="/operators/k5.example"');
    expect(document).toContain("1F916:k5");
    expect(document).toContain("2026-09-11 09:00:00Z");
    expect(document).toContain("held");
    // The one nomankind opened itself, and the one nothing has been drawn for.
    expect(document).toContain("nomankind, from failure reports");
    expect(document).toContain(`<span class="dim">not yet drawn</span>`);
  });

  it("lists the stakes, and never prices what the log left unpriced", () => {
    expect(document).toContain(">Stakes</h2>");
    expect(document).toContain("dispute_stake");
    expect(document).toContain("dispute_reward");
    expect(document).toContain("10 standing");
    expect(document).toContain(`<span class="dim">unpriced</span>`);
    expect(document).toContain("<td class=\"dim\">41</td>");
    expect(document).toContain("<td class=\"dim\">42</td>");
    // The sentence about the placeholders spells no number of its own.
    expect(document).toContain("No money moves on any of these rows.");
  });

  it("links the entry this one was filed against, both ways", () => {
    expect(document).toContain("<dt>dispute of</dt>");
    expect(document).toContain(`<a href="/entries/${DISPUTED_ID}">`);
    // overturned_by is the other direction and is a link too.
    expect(document).toContain("<dt>overturned_by</dt>");
    expect(document).toContain(`<a href="/entries/${OTHER_ID}">`);
  });

  it("says nothing was filed rather than showing four empty tables", () => {
    const quiet = renderEntry(ctx, {
      ...entryData,
      entry: { ...entryRecord, disputes: [], failure_reports: [] },
      sidecar: { ...sidecar, revalidations: [] },
      ledger: [],
      disputeOf: null,
    });
    expect(quiet).toContain("No dispute has been filed.");
    expect(quiet).toContain("No failure report has been filed.");
    expect(quiet).toContain("No revalidation has been requested.");
    expect(quiet).toContain("No stake has been recorded.");
    expect(quiet).not.toContain("<dt>dispute of</dt>");
  });
});

describe("the operator pages", () => {
  const directory = renderOperators(ctx, {
    rows: [
      operatorRow,
      {
        ...operatorRow,
        id: "maintainer.example",
        maintainer: true,
        trusted: false,
        trustedSeq: null,
        validations: 0,
        overturned: 0,
      },
    ],
  });

  it("names the maintainer as one that cannot validate", () => {
    expect(directory).toContain("cannot validate");
    expect(directory).toContain('<a href="/operators/maintainer.example">');
    expect(directory).toContain("not yet published (M21)");
  });

  it("fills the overturned column with a count, and a zero with a zero", () => {
    // The column is a reading of the log now that the dispute door exists, so
    // the milestone placeholder is gone and an operator nothing was overturned
    // for shows 0 rather than a sentence about a milestone.
    expect(directory).not.toContain("not yet published (M20)");
    expect(directory).toContain(`<td class="danger">\n      2\n    </td>`);
    expect(directory).toContain(`<td class="dim">\n      0\n    </td>`);
    expect(directory).toContain(
      "entries this operator signed, as\n        submitter or as approver, that an upheld dispute overturned",
    );
  });

  it("shows one operator's record, agents, attestation and validations", () => {
    const one = renderOperator(ctx, {
      row: operatorRow,
      agents: ["1F916:k1"],
      attestation: {
        version: "nomankind-independence-v1",
        signed_at: "2026-08-01T00:00:00.000Z",
        signature: "YXR0ZXN0",
      },
      namedBy: "1F916:maintainer",
      payoutStatus: "onboarded",
      validations: [
        {
          entryId: ENTRY_ID,
          decision: "approve",
          seq: 14,
          signed_at: "2026-09-08T12:00:00.000Z",
        },
      ],
    });
    expect(one).toContain("nomankind-independence-v1");
    expect(one).toContain("YXR0ZXN0");
    expect(one).toContain("1F916:maintainer");
    expect(one).toContain("onboarded");
    expect(one).toContain(`<a href="/entries/${ENTRY_ID}">`);
    expect(one).toContain("<dt>registered seq</dt>");
    expect(one).toContain("<dt>overturned</dt>");
    expect(one).toContain(`<dd class="danger">\n                2\n              </dd>`);
  });

  it("says an operator has signed nothing rather than showing an empty table", () => {
    const quiet = renderOperator(ctx, {
      row: { ...operatorRow, validations: 0, agents: 0, overturned: 0 },
      agents: [],
      attestation: null,
      namedBy: null,
      payoutStatus: null,
      validations: [],
    });
    expect(quiet).toContain("This operator has signed no decisions.");
    expect(quiet).toContain("No agent is bound.");
    expect(quiet).toContain("No attestation is stored on this row.");
  });
});

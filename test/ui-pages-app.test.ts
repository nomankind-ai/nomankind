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
import { renderEntries } from "../src/ui/pages/entries.js";
import { renderEntry } from "../src/ui/pages/entry.js";
import { renderHome } from "../src/ui/pages/home.js";
import { renderOperator } from "../src/ui/pages/operator.js";
import { renderOperators } from "../src/ui/pages/operators.js";
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

const HASH =
  "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_HASH =
  "sha256:2222222222222222222222222222222222222222222222222222222222222222";

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
};

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
  disputes: [],
  failure_reports: [],
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
      },
    ],
  });

  it("names the maintainer as one that cannot validate", () => {
    expect(directory).toContain("cannot validate");
    expect(directory).toContain('<a href="/operators/maintainer.example">');
    expect(directory).toContain("not yet published (M21)");
    expect(directory).toContain("not yet published (M20)");
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
  });

  it("says an operator has signed nothing rather than showing an empty table", () => {
    const quiet = renderOperator(ctx, {
      row: { ...operatorRow, validations: 0, agents: 0 },
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

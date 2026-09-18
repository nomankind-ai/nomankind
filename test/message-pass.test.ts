/**
 * The message pass (M25f): every app page says what the record is now.
 *
 * The record was once sold by the month — a holdback window, a price per read,
 * a share of it for the operators who backed an entry. None of that is true any
 * more (decisions D-100 and D-127), and the pages were rewritten to say so one
 * negation at a time: "no read is priced", "no paid tier", "no read-share
 * slot". A page that keeps telling a reader what it does not charge is still a
 * page about charging, so this suite holds every page to the positive form. The
 * vocabulary of the old design is refused outright, with one exception: a
 * sentence that is explicitly marked as history, because `RELEASE_WINDOW_DAYS`
 * is still in the policy object and still written into every mirror manifest,
 * and a reader of a v1 clone has to be told what they are looking at.
 *
 * Three other things are pinned here. The landing page's one sentence, exactly
 * (D-131 item 1), because a sentence that is nearly right is a different
 * sentence. The entry page's attestation column (D-140 item 7), which says
 * which independence sentence a public confirmation stood behind. And the docs
 * hub's whitepaper card, which must read the version the paper itself says it
 * is once `npm run gen:docs` has rendered it.
 *
 * Pure: every page in src/ui/pages/ is a function of a gathered object, so the
 * fixtures below are written by hand and nothing here opens a store, a clock or
 * the network.
 */

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { attributionOf } from "../src/attribution.js";
import { confidenceInputs } from "../src/confidence.js";
import type { Sidecar } from "../src/derive.js";
import type { Event } from "../src/events.js";
import {
  independenceReport,
  type ValidatorEntry,
} from "../src/independence.js";
import { ledgerBalance } from "../src/ledger.js";
import {
  DEFAULT_DOMAIN,
  DOMAIN_SLUGS,
  POLICY,
  WITNESS_PIN,
  attestationFor,
} from "../src/policy.js";
import type { Entry } from "../src/schema.js";
import type { Seal } from "../src/seal.js";
import { tierOf } from "../src/standing.js";
import type { Counter, Stage } from "../src/status.js";
import { WHITEPAPER_MARKDOWN } from "../src/ui/docs.generated.js";
import { escapeHtml } from "../src/ui/html.js";
import { renderApi } from "../src/ui/pages/api.js";
import { renderDocs } from "../src/ui/pages/docs.js";
import { WHITEPAPER_VERSION } from "../src/ui/pages/document.js";
import { renderDomains } from "../src/ui/pages/domains.js";
import { renderDryRun } from "../src/ui/pages/dry-run.js";
import { renderEntries } from "../src/ui/pages/entries.js";
import { renderEntry } from "../src/ui/pages/entry.js";
import { renderGenesis } from "../src/ui/pages/genesis.js";
import { renderHome } from "../src/ui/pages/home.js";
import { renderHowItWorks } from "../src/ui/pages/how-it-works.js";
import { renderIndependence } from "../src/ui/pages/independence.js";
import { renderLanding } from "../src/ui/pages/landing.js";
import { renderMirror } from "../src/ui/pages/mirror.js";
import { renderOperator } from "../src/ui/pages/operator.js";
import { renderOperators } from "../src/ui/pages/operators.js";
import { RELEASE_HISTORY, renderPolicy } from "../src/ui/pages/policy.js";
import { renderStatus } from "../src/ui/pages/status.js";
import { renderTerms } from "../src/ui/pages/terms.js";
import type {
  EntriesData,
  EntryData,
  EntryRow,
  HowItWorksData,
  LandingData,
  MirrorData,
  OperatorData,
  OperatorRow,
  PageContext,
  StatusData,
} from "../src/ui/types.js";

// ---------------------------------------------------------------------------
// The words, and the one sentence allowed to keep them
// ---------------------------------------------------------------------------

/**
 * The vocabulary of the design this record abandoned.
 *
 * Every one of these is refused wherever it appears, in the negative as much as
 * in the positive: "no read-share slot" is a sentence about read-share slots.
 * The words a live rule still uses are not here — a freshness window, a
 * disclosure window, a vote window and an assignment window are all things the
 * kernel does today, and a domain's `pricing` category is a fact the record
 * keeps about the world rather than a fact about itself.
 */
const RETIRED: readonly { readonly word: string; readonly pattern: RegExp }[] = [
  { word: "priced", pattern: /\bpric(?:ed|ing this|e per read)\b/i },
  { word: "payout", pattern: /\bpaid out\b|\bpayouts?\b/i },
  { word: "paid tier", pattern: /\bpaid (?:tier|door|product)\b/i },
  { word: "read share", pattern: /\bread[- ]shares?\b/i },
  { word: "contributor share", pattern: /\bcontributor share\b/i },
  { word: "bounty", pattern: /\bbount(?:y|ies)\b/i },
  { word: "withheld", pattern: /\bwithh(?:eld|olds?|olding)\b/i },
  { word: "slot", pattern: /\bslots?\b/i },
  { word: "Stripe", pattern: /\bstripe\b/i },
  { word: "holdback", pattern: /\bholdbacks?\b/i },
  { word: "paywall", pattern: /\bpaywall\w*/i },
  { word: "release window", pattern: /\brelease window\b/i },
  { word: "on sale", pattern: /\b(?:on|for) sale\b|\bis sold\b/i },
  { word: "purchase", pattern: /\bpurchas(?:e|es|ed|ing)\b/i },
  { word: "money", pattern: /\bmoney\b/i },
  { word: "revenue", pattern: /\brevenues?\b/i },
  { word: "fee", pattern: /\bfees?\b/i },
  { word: "micro-USD", pattern: /\bmicro-?usd\b/i },
  { word: "a price in a currency", pattern: /\$\s?\d/ },
];

/**
 * The sentences allowed to carry the old words, because they are marked as
 * history in their own first word.
 *
 * One of them, and it is the policy page's reading of `RELEASE_WINDOW_DAYS`:
 * the number is zero and has no code behind it, but it is still in the policy
 * object and still in every mirror manifest, so a reader of an old clone has to
 * be told what that column was. Imported rather than retyped — a copy here
 * would let the page and the allowance drift apart, which is the whole failure
 * this suite exists to catch.
 */
const HISTORY: readonly string[] = [RELEASE_HISTORY];

/** The document with every history sentence cut out of it, escaped as the page prints it. */
function scrub(document: string): string {
  let text = document;
  for (const sentence of HISTORY) {
    text = text.split(escapeHtml(sentence)).join(" ");
    text = text.split(sentence).join(" ");
  }
  return text;
}

/** Every retired word refused on one page. */
function expectClean(name: string, document: string): void {
  const text = scrub(document);
  for (const { word, pattern } of RETIRED) {
    const found = pattern.exec(text);
    expect(
      found,
      `${name} still says "${word}"${found === null ? "" : `: …${text.slice(Math.max(0, found.index - 90), found.index + 90)}…`}`,
    ).toBeNull();
  }
}

// ---------------------------------------------------------------------------
// The fixtures: one of each shape the routes gather
// ---------------------------------------------------------------------------

const ctx: PageContext = {
  environment: "demo",
  path: "/",
  origin: "https://demo.nomankind.ai",
  canonical_origin: "https://demo.nomankind.ai",
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
  subject: "kestrel/kestrel-1",
  category: "behavior",
  domain: "ai-safety",
  claim: "The model refuses this prompt",
  tier: "stated",
  verification_class: "mixed",
  verification_binding: null,
  last_confirmed: "2026-09-08",
  expires_at: "2026-10-08",
  stale: true,
};

/**
 * One confirmation of each kind (D-140 item 7): a line that put the
 * independence sentence behind it, and one that attested nothing. Two rows,
 * because a column with one value in it would pass whatever the page printed.
 */
const CONFIRMATIONS: Sidecar["confirmations"] = [
  {
    venue: "1f916",
    handle: "citizen-one",
    verdict: "approve",
    check: { kind: "hash", value: HASH },
    reason: null,
    posted_at: "2026-09-15T09:00:00.000Z",
    registry_event_id: 11_709,
    counted: true,
    attestation_version: attestationFor(DEFAULT_DOMAIN).version,
    seq: 41,
  },
  {
    venue: "1f916",
    handle: "citizen-two",
    verdict: "approve",
    check: { kind: "span", value: "present" },
    reason: null,
    posted_at: "2026-09-15T10:00:00.000Z",
    registry_event_id: 11_710,
    counted: false,
    attestation_version: null,
    seq: 42,
  },
];

const sidecar: Sidecar = {
  confirmations: CONFIRMATIONS,
  bootstrap: { perimeter: "fixtures" },
  needs_replacement: false,
  effective_tier: "stated",
  test_verdict: "rejected",
  source: {
    class: "official",
    matched_host: "docs.kestrel.example",
    authority: "kestrel",
  },
  trusted_count_at_decision: 3,
  verification_class: "mixed",
  verification_communities: ["1f916"],
  verification_single_venue: true,
  verification_binding: null,
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
  read_share_slots: null,
  revalidations: [],
};

const entryRecord: Record<string, unknown> = {
  id: ENTRY_ID,
  subject: row.subject,
  category: "behavior",
  domain: DEFAULT_DOMAIN,
  claim: row.claim,
  before: "the model answered",
  after: "the model refuses",
  effective_at: "2026-09-01",
  evidence_tier: "observed",
  evidence: {
    model: "kestrel-1",
    prompt: "say something",
    parameters: { temperature: 0 },
    output: "I cannot help with that.",
    predicate: "the model refuses this prompt",
    observed_at: "2026-09-01",
    provider_statement: null,
  },
  observation: null,
  citation: "https://kestrel.example/transcript",
  snapshot_hash: HASH,
  norm_version: POLICY.NORM_VERSION,
  supersedes: null,
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
      reproduction: null,
      observation: null,
      signed_at: "2026-09-08T12:00:00.000Z",
    },
  ],
  reconfirmations: [],
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
  overturned_by: null,
  status: "verified",
  confidence: null,
};

const events: Event[] = [
  {
    seq: 12,
    at: "2026-09-08T12:00:00.000Z",
    type: "entry_submitted",
    entry_id: ENTRY_ID,
    payload: { core: {} as never, signature: "c2lnbmF0dXJl" },
    prev_hash: null,
    hash: OTHER_HASH,
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
  confidenceInputs: confidenceInputs({
    entry: entryRecord as unknown as Entry,
    sidecar,
    now: "2026-09-20T06:00:00.000Z",
  }),
  attribution: attributionOf(
    entryRecord as unknown as Entry,
    events,
    new Map(),
  ),
  position: 12,
  events,
  seal,
  approvers: [
    {
      agent: "1F916:k1",
      operator: "k1.example",
      operatorKind: "domain",
      community: null,
      operatorTrusted: true,
      decision: "approve",
      reason: null,
      snapshot_hash: HASH,
      assigned_random: false,
      test_accepted: false,
      reproduction: null,
      observation: null,
      signed_at: "2026-09-08T12:00:00.000Z",
      seq: 14,
    },
  ],
  reconfirmations: [],
  superseders: [],
  stalenessWindowDays: 30,
  ledger: [],
  readShares: [],
  disputeOf: null,
  statement: null,
  disclosure: null,
};

const operatorRow: OperatorRow = {
  id: "k1.example",
  kind: "domain",
  community: null,
  maintainer: false,
  provider: false,
  trusted: true,
  perimeter: "fixtures",
  trustedSeq: 5,
  registeredSeq: 2,
  agents: 1,
  domainSlugs: [DEFAULT_DOMAIN],
  validations: 7,
  overturned: 1,
  standing: { standing: 14, seq: 61 },
  counts: {
    validations_volunteered: 3,
    validations_assigned: 4,
    validations_reproduced: 2,
    attestations_scored: 1,
    submissions_verified: 2,
    disputes_upheld: 1,
    revalidations_changed: 0,
    overturned: 1,
    missed: 1,
    forfeits: 1,
  },
  tier: tierOf(14, true),
  cosigners: 0,
};

const operatorData: OperatorData = {
  row: operatorRow,
  agents: ["1F916:k1"],
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
  marks: { overturned: [], missed: [], failed_disputes: [] },
  validations: [],
  cosigners: [],
  ledger: [],
  balance: ledgerBalance([], "2026-09-09T00:00:00.000Z"),
  attestations: { asModel: [], asScorer: [] },
};

const entriesData: EntriesData = {
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
  rows: [row],
  total: 1,
  nextBefore: null,
};

const landingData: LandingData = {
  seals: [
    {
      seq: 0,
      hash: HASH,
      sealedAt: "2026-09-09T17:47:27.000Z",
      witnessed: true,
      events: 4,
    },
  ],
  sealCount: 1,
  witnesses: 2,
  verified: 9,
};

const pipeline: HowItWorksData = {
  entry: null,
  capture: null,
  pool: { names: [], trusted: 0, registered: 0 },
  validation: null,
  seal: null,
  anchor: null,
  readCount: null,
  overturned: null,
  stale: 0,
  nextWindowEnds: null,
  standing: { position: null, rows: [] },
  reconciliation: null,
  attestation: null,
  syncFrom: 0,
  mirror: null,
};

const mirrorData: MirrorData = {
  configured: true,
  kind: "github",
  repository: "https://github.com/nomankind-ai/log",
  branch: "main",
  path: "demo",
  latest: {
    date: "2026-09-10",
    exported_at: "2026-09-10T00:04:11.000Z",
    commit: "9f2c1ab4c5d6e7f8091a2b3c4d5e6f7081920304",
    tree: "1122334455667788990011223344556677889900",
    head: 54,
    seal_seq: 11,
    entries: 9,
    files_changed: 3,
    url: "https://github.com/nomankind-ai/log/tree/9f2c1ab/demo",
    raw_url: "https://raw.githubusercontent.com/nomankind-ai/log/9f2c1ab/demo/mirror.json",
  },
};

const counter: Counter = {
  lastSweepAt: "2026-09-10T14:05:07.000Z",
  lastSweepAge: "2 min ago",
  lastSweepTrigger: "alarm",
  stagesOk: 13,
  stagesTotal: 13,
  stagesFailing: 0,
  stagesAttention: 0,
  sealedHead: 54,
  newestSealSeq: 11,
  unsealedEvents: 0,
  seals: 11,
  witnessedSeals: 11,
  witnessKind: "mock witnesses on demo",
};

const stage: Stage = {
  stage: "sealing",
  state: "ok",
  last: "the newest seal covers the head",
  rule: "SEAL_INTERVAL_MINUTES",
  evidence: [{ label: "newest seal", href: "/seals/11" }],
};

const statusData: StatusData = {
  asOf: "2026-09-10T14:05:07.000Z",
  counters: counter,
  stages: [stage],
  exercised: [],
};

const validators: readonly ValidatorEntry[] = [
  {
    operator: "k1.example",
    kind: "domain",
    venue: null,
    handle: null,
    trusted: true,
    maintainer: false,
    provider: false,
    domains: [DEFAULT_DOMAIN],
    perimeter: "fixtures",
  },
];

const independenceData = {
  report: independenceReport({
    validators,
    pin: WITNESS_PIN,
    counted: [],
    boundOperators: new Map<string, string>(),
    sealSeq: 11,
  }),
};

/** Every page this pass covers, by the path a reader reaches it at. */
const PAGES: Readonly<Record<string, string>> = Object.freeze({
  "/": renderLanding({ ...ctx, path: "/" }, landingData),
  "/home": renderHome(
    { ...ctx, path: "/home" },
    {
      counters: {
        verified: 9,
        stale: 2,
        trusted: 3,
        sealedHead: 54,
        sealedAt: "2026-09-10T14:05:07.000Z",
        witnesses: 2,
        seals: 11,
      },
      latest: [row],
      domain: null,
    },
  ),
  "/how-it-works": renderHowItWorks({ ...ctx, path: "/how-it-works" }, pipeline),
  "/docs": renderDocs({ ...ctx, path: "/docs" }),
  "/api": renderApi({ ...ctx, path: "/api" }),
  "/policy": renderPolicy({ ...ctx, path: "/policy" }, POLICY),
  "/domains": renderDomains(
    { ...ctx, path: "/domains" },
    {
      counts: Object.fromEntries(
        DOMAIN_SLUGS.map((slug) => [slug, { entries: 4, trustedOperators: 3 }]),
      ),
    },
  ),
  "/genesis": renderGenesis(
    { ...ctx, path: "/genesis" },
    {
      rows: [],
      attestationText: attestationFor(DEFAULT_DOMAIN).text,
      attestationVersion: attestationFor(DEFAULT_DOMAIN).version,
      txtRecordPrefix: "_nomankind",
      maintainerConfigured: false,
    },
  ),
  "/independence": renderIndependence(
    { ...ctx, path: "/independence" },
    independenceData,
  ),
  "/dry-run": renderDryRun({ ...ctx, path: "/dry-run" }),
  "/entries": renderEntries({ ...ctx, path: "/entries" }, entriesData),
  "/entries/{id}": renderEntry(
    { ...ctx, path: `/entries/${ENTRY_ID}` },
    entryData,
  ),
  "/operators": renderOperators(
    { ...ctx, path: "/operators" },
    { rows: [operatorRow], bareKeys: [] },
  ),
  "/operators/{id}": renderOperator(
    { ...ctx, path: "/operators/k1.example" },
    operatorData,
  ),
  "/mirror/latest": renderMirror({ ...ctx, path: "/mirror/latest" }, mirrorData),
  "/status": renderStatus({ ...ctx, path: "/status" }, statusData),
  // The terms of use and privacy note (D-097 item 2 as rewritten under D-127).
  // The page whose whole subject is that none of this is bought, which is the
  // one page most likely to reach for the vocabulary of the thing it is denying:
  // "no purchase terms" is a sentence about purchase terms, exactly as "no
  // read-share" is a sentence about read shares.
  "/terms": renderTerms({ ...ctx, path: "/terms" }),
});

// ---------------------------------------------------------------------------
// The pass itself
// ---------------------------------------------------------------------------

describe("the message pass: no page sells anything", () => {
  for (const [path, document] of Object.entries(PAGES)) {
    it(`${path} carries none of the retired words`, () => {
      expect(document.length).toBeGreaterThan(0);
      expectClean(path, document);
    });
  }

  it("keeps exactly one sentence of history, and marks it as one", () => {
    const policy = PAGES["/policy"]!;
    expect(policy).toContain(escapeHtml(RELEASE_HISTORY));
    expect(RELEASE_HISTORY.startsWith("History:")).toBe(true);
    // And it is the only page allowed to carry one: cut it out and the policy
    // page is as clean as every other.
    for (const [path, document] of Object.entries(PAGES)) {
      if (path === "/policy") continue;
      for (const sentence of HISTORY) {
        expect(document, `${path} carries a history sentence`).not.toContain(
          escapeHtml(sentence),
        );
      }
    }
  });
});

describe("the landing page's one sentence (D-131 item 1)", () => {
  const page = PAGES["/"]!;

  it("prints it exactly, and as the page's own line", () => {
    expect(page).toContain(
      '<p class="hero-sub">nomankind is a free, tamper-evident record of ' +
        "verified facts about AI, independent of every lab, for models that " +
        "keep learning.</p>",
    );
  });

  it("names the three registered domains under it, AI safety first", () => {
    const flat = page.replace(/\s+/g, " ");
    expect(flat).toContain(
      "Three registered domains: AI safety, AI governance, and the AI ecosystem.",
    );
    const safety = flat.indexOf("AI safety,");
    expect(safety).toBeGreaterThan(-1);
    expect(safety).toBeLessThan(flat.indexOf("AI governance,"));
    expect(flat.indexOf("AI governance,")).toBeLessThan(
      flat.indexOf("and the AI ecosystem."),
    );
  });

  it("keeps the footer the decision left alone", () => {
    expect(page).toContain(
      "CODE APACHE-2.0 · DATA CC0 FROM THE SEAL · TRAINING ON THE DATA IS FREE",
    );
  });

  it("follows the five words, and says whose the bootstrap pool is", () => {
    const flat = page.replace(/\s+/g, " ");
    for (const word of [
      "Free.",
      "Trustworthy.",
      "Tamper-evident.",
      "Poison-free.",
      "Lab-independent.",
      "For models that keep learning.",
    ]) {
      expect(flat, `the landing page drops "${word}"`).toContain(word);
    }
    expect(flat).toContain("No lab funds, runs, or validates the record.");
    expect(flat).toContain(
      "The pool that started it is nomankind&#39;s own, disclosed as a " +
        "bootstrap perimeter on every entry it signed, and replaced as outside " +
        "operators join",
    );
  });
});

describe("the entry page's attestation column (D-140 item 7)", () => {
  const page = PAGES["/entries/{id}"]!;

  it("names the version a confirmation attested, and says so when it attested none", () => {
    const flat = page.replace(/\s+/g, " ");
    expect(flat).toContain(
      `attested ${attestationFor(DEFAULT_DOMAIN).version}`,
    );
    expect(flat).toContain("no attestation");
    expect(flat).toContain("<th>attestation</th>");
  });

  it("says what the column is, beside the table", () => {
    const flat = page.replace(/\s+/g, " ");
    expect(flat).toContain(
      "The attestation column is the independence sentence the line itself carried",
    );
  });
});

describe("the docs hub's whitepaper card", () => {
  it("reads the version the paper says it is, once gen:docs has rendered it", () => {
    expect(WHITEPAPER_VERSION).toBe("v1.7");
    expect(PAGES["/docs"]).toContain(
      `The specification, consolidated at ${WHITEPAPER_VERSION}.`,
    );
    // The rendered module is the paper's own bytes, so this fails until
    // `npm run gen:docs` has run over F1's v1.7.
    expect(WHITEPAPER_MARKDOWN).toContain("This is v1.7");
  });
});

// ---------------------------------------------------------------------------
// The documents the pages were rewritten from
// ---------------------------------------------------------------------------

/**
 * The same pass over the prose (M25f): the paper and every document that
 * follows it.
 *
 * A page that stopped charging while the paper it is rendered from still
 * priced things would be two records, so the documents are held to the
 * vocabulary the pages are. The list is narrower than `RETIRED` on purpose:
 * a document may say "money" where a page may not, because a document is
 * allowed to explain what the record does not do — "measurement costs money,
 * and whoever measures carries that cost" is a true sentence about the world
 * and not an offer.
 */
const DOCUMENTS: readonly string[] = [
  "paper/WHITEPAPER.md",
  "paper/SUMMARY.md",
  "README.md",
  "CONTRIBUTING.md",
  "docs/FORK.md",
  "docs/LOG-REPOSITORY-README.md",
];

/** The nine words no document may carry in its own prose. */
const DOCUMENT_WORDS: readonly { readonly word: string; readonly pattern: RegExp }[] =
  RETIRED.filter(({ word }) =>
    [
      "read share",
      "contributor share",
      "bounty",
      "payout",
      "release window",
      "withheld",
      "Stripe",
      "holdback",
      "slot",
    ].includes(word),
  );

/**
 * The sentences a document is allowed to keep them in, exactly as written.
 *
 * Both are history in their own first words, which is the only allowance
 * anywhere in this suite: a reader of a v1.6 clone, or of a fork that still
 * runs a window, has to be told what they are looking at. The paper's own
 * dated change note is allowed the same way, by its opening, because a labeled
 * amendment that could not name what it retired would not be one.
 */
const DOCUMENT_HISTORY: Readonly<Record<string, readonly string[]>> = {
  "README.md": [
    "The third step v1.6 asked for, payout onboarding with a payment provider, " +
      "is gone with the money (D-127), and no door writes or reads a payout " +
      "reference any more.",
    "The release window v1.6 published — thirty days between an entry's seal " +
      "and its content — is history",
  ],
};

/** The paper's change note: one line, allowed by its opening. */
const CHANGE_NOTE = "*Changes in v1.7,";

/** Inline code and fenced blocks are not prose: a door's own word is its own. */
function prose(markdown: string): string {
  return markdown
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`[^`\n]*`/g, " ")
    .split("\n")
    .filter((line) => !line.startsWith(CHANGE_NOTE))
    .join("\n");
}

describe("the message pass: no document sells anything either", () => {
  for (const path of DOCUMENTS) {
    it(`${path} carries none of the retired words`, () => {
      const markdown = readFileSync(
        new URL(`../${path}`, import.meta.url),
        "utf8",
      );
      expect(markdown.length).toBeGreaterThan(0);
      let text = prose(markdown);
      for (const sentence of DOCUMENT_HISTORY[path] ?? []) {
        expect(
          text,
          `${path} no longer carries the history sentence this suite allows`,
        ).toContain(sentence);
        text = text.split(sentence).join(" ");
      }
      for (const { word, pattern } of DOCUMENT_WORDS) {
        const found = pattern.exec(text);
        expect(
          found,
          `${path} still says "${word}"${found === null ? "" : `: …${text.slice(Math.max(0, found.index - 90), found.index + 90)}…`}`,
        ).toBeNull();
      }
    });
  }

  it("allows the paper one change note, and only by its label", () => {
    const paper = readFileSync(
      new URL("../paper/WHITEPAPER.md", import.meta.url),
      "utf8",
    );
    const notes = paper
      .split("\n")
      .filter((line) => line.startsWith(CHANGE_NOTE));
    expect(notes).toHaveLength(1);
    expect(notes[0]).toContain("D-127");
  });
});

/**
 * The two pages M22 adds: How it works, and Status (D-076).
 *
 * Both are pages about the machine rather than views of one record, and both
 * make a promise the tests here hold them to. How it works promises that every
 * stage it describes links to this environment's own log — and that on a log
 * holding nothing, which is what production is the day it opens, it says so in
 * words instead of showing a plan. Status promises that every light is a rule
 * applied to the sweep's stored report, that the band appears only when
 * something is actually wrong, and that the four states are told apart by the
 * four badge classes the rest of this UI already uses.
 *
 * The fixtures are the contract's shapes and nothing here touches a database:
 * `stageStates`, `exercisedStages` and `statusCounters` are src/status.ts's, and
 * these pages are pure functions of what those returned.
 */

import { describe, expect, it } from "vitest";
import {
  DEFAULT_DOMAIN,
  NORM_VERSION,
  SCHEMA_VERSION,
  SWEEP_INTERVAL_MINUTES,
  TRUSTED_POOL_SWITCH,
} from "../src/policy.js";
import type { Counter, Exercised, Stage } from "../src/status.js";
import { renderHowItWorks } from "../src/ui/pages/how-it-works.js";
import { APP_CSS } from "../src/ui/styles.js";
import { renderStatus } from "../src/ui/pages/status.js";
import type {
  HowItWorksData,
  PageContext,
  StatusData,
} from "../src/ui/types.js";

const ctx: PageContext = {
  environment: "demo",
  path: "/how-it-works",
  origin: "https://demo.nomankind.ai",
};

const statusCtx: PageContext = { ...ctx, path: "/status" };

/** A document with its whitespace collapsed, for a sentence that wraps. */
function flat(document: string): string {
  return document.replace(/\s+/g, " ");
}

const ENTRY_ID = "nmk_4d7c5efb907732f6a54de4d958078663";
const CORRECTION_ID = "nmk_aa3ce28b0b1d4d6e9d0b6a6f0c9b515d";
const CAPTURE_HASH =
  "sha256:13f5e50297bde87abbf51cd1cd43678109b1a72a52c1cefa3b56844464e4f25c";

/** A log with something in it at every stage: what demo looks like. */
const LIVE: HowItWorksData = {
  entry: {
    id: ENTRY_ID,
    status: "verified",
    tier: "stated",
    domain: DEFAULT_DOMAIN,
  },
  capture: {
    hash: CAPTURE_HASH,
    host: "example.com",
    normVersion: NORM_VERSION,
  },
  pool: {
    names: ["fixture-c", "fixture-d", "fixture-e"],
    trusted: 3,
    registered: 5,
  },
  validation: { seq: 48, decision: "approve", operator: "fixture-d" },
  seal: {
    seq: 11,
    firstSeq: 52,
    lastSeq: 54,
    witnesses: 2,
    sealedAt: "2026-09-10T14:00:19.000Z",
  },
  anchor: { date: "2026-09-09", seals: 1, external: "local on demo" },
  readCount: {
    seq: 17,
    date: "2026-09-09",
    total: 17,
    counterFirst: 1,
    counterLast: 19,
  },
  overturned: { id: CORRECTION_ID, correction: ENTRY_ID },
  stale: 0,
  nextWindowEnds: "2026-12-07",
  standing: {
    position: 54,
    rows: [
      { operator: "fixture-c", standing: 4 },
      { operator: "fixture-d", standing: 1 },
    ],
  },
  reconciliation: { date: "2026-09-09", published: 17, accrued: 17, ok: true },
  attestation: {
    id: "att_ce8252943fd4611e759c43d57f04318b",
    status: "scored",
    score: "1 / 1",
    date: "2026-09-10",
    scorers: ["fixture-e", "fixture-c"],
  },
  syncFrom: 43,
};

/** A log holding nothing at all: what production is on the day it opens. */
const EMPTY: HowItWorksData = {
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
};

/** The eight panels, as the artboard heads them. */
const PANELS: readonly { readonly id: string; readonly number: string; readonly title: string; readonly label: string }[] =
  [
    { id: "s1", number: "01", title: "Submit and snapshot", label: "SECTION 6 · SUBMIT" },
    { id: "s2", number: "02", title: "Validate", label: "SECTION 6 · VALIDATE" },
    { id: "s3", number: "03", title: "Seal, witness, anchor", label: "SECTION 6 · SEAL" },
    { id: "s4", number: "04", title: "Read with a receipt", label: "SECTION 8 · THE TRAINING PATH" },
    {
      id: "s5",
      number: "05",
      title: "Keep it true",
      label: "SECTIONS 6 AND 7 · RECONFIRM, SUPERSEDE, DISPUTE",
    },
    { id: "s6", number: "06", title: "Standing and the ledger", label: "SECTION 9 · INCENTIVES" },
    { id: "s7", number: "07", title: "Attest a model", label: "SECTION 8 · DRIFT ATTESTATION" },
    { id: "s8", number: "08", title: "Verify offline", label: "GOAL 4 · TWO FILES AND ONE SCRIPT" },
  ];

describe("renderHowItWorks", () => {
  const page = renderHowItWorks(ctx, LIVE);

  it("carries the eight panels, each with its heading and its section label", () => {
    for (const panel of PANELS) {
      expect(page, `${panel.title} has no panel`).toContain(
        `id="${panel.id}"`,
      );
      expect(page, `${panel.title} is not headed`).toContain(panel.title);
      expect(page, `${panel.title} carries no number`).toContain(
        `<span class="stage-num">${panel.number}</span>`,
      );
      expect(page, `${panel.title} carries no section label`).toContain(
        panel.label,
      );
    }
  });

  it("puts the eight steps across the top, each anchored at its panel", () => {
    expect(page).toContain('class="steps"');
    for (const panel of PANELS) {
      expect(page, `no step for ${panel.title}`).toContain(
        `class="step" href="#${panel.id}"`,
      );
    }
  });

  it("styles the strip through the selector the markup actually uses", () => {
    // Each step is itself the anchor, so the sheet says `a.step`; a `.step a`
    // rule would match nothing on this page and quietly style nothing.
    expect(page).toContain(`<a class="step"`);
    expect(APP_CSS).toContain("a.step {");
    expect(APP_CSS).not.toContain(".step a {");
  });

  it("links every live value into this environment's own log", () => {
    expect(page).toContain(`href="/entries/${ENTRY_ID}"`);
    expect(page).toContain(`href="/captures/${CAPTURE_HASH}"`);
    expect(page).toContain('href="/operators"');
    expect(page).toContain('href="/events/48"');
    expect(page).toContain('href="/seals/11"');
    expect(page).toContain('href="/anchors/2026-09-09"');
    expect(page).toContain('href="/events/17"');
    expect(page).toContain(`href="/read/${ENTRY_ID}"`);
    expect(page).toContain("/sync?from=43");
    expect(page).toContain('href="/entries?fresh=stale"');
    expect(page).toContain('href="/standing"');
    expect(page).toContain('href="/ledger"');
    expect(page).toContain(
      'href="/attestations/att_ce8252943fd4611e759c43d57f04318b"',
    );
    expect(page).toContain(`href="/entries/${ENTRY_ID}/confidence-inputs"`);
  });

  it("names the versions and the policy numbers it read rather than its own", () => {
    expect(page).toContain(`schema ${SCHEMA_VERSION}`);
    expect(page).toContain(NORM_VERSION);
    expect(page).toContain(`switch at ${TRUSTED_POOL_SWITCH}`);
    expect(page).toContain(`SCHEMA_VERSION ${SCHEMA_VERSION}`);
    expect(page).toContain("STANDING_TRUSTED_ENTRY");
    expect(page).toContain("PROBE_SET_SIZE");
  });

  it("spells the export and verify commands against the request's origin", () => {
    expect(page).toContain(`npm run export -- ${ctx.origin} ${ENTRY_ID} ./out`);
    expect(page).toContain("npm run verify -- ./out/entry.json ./out/log.json");
  });

  it("says every missing value in words on a log that holds nothing", () => {
    const empty = renderHowItWorks(ctx, EMPTY);
    for (const words of [
      "no entry yet",
      "no capture yet",
      "no trusted operator yet",
      "no validation yet",
      "no seal yet",
      "no anchor yet",
      "no read count yet",
      "no entry to read yet",
      "no overturned entry",
      "none stale",
      "no standing computed yet",
      "no reconciliation yet",
      "no attestation yet",
    ]) {
      expect(empty, `the empty page never says "${words}"`).toContain(words);
    }
    // And the eight panels are still all there: an empty log is a log, and the
    // page explains the machine either way.
    for (const panel of PANELS) {
      expect(empty, `${panel.title} vanished on an empty log`).toContain(
        panel.title,
      );
    }
    // Nothing is dashed out and nothing pretends there is a record to read.
    expect(empty).not.toContain("nmk_");
  });

  it("carries no script and no inline style", () => {
    for (const document of [page, renderHowItWorks(ctx, EMPTY)]) {
      expect(document).not.toContain("<script");
      expect(document).not.toContain(' style="');
    }
  });
});

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/** Every stage, in the order the pipeline runs them. */
const STAGE_NAMES: readonly string[] = [
  "sweep timer",
  "pool snapshot",
  "beacon",
  "draws and deadlines",
  "staleness",
  "read counts",
  "sealing",
  "witnessing",
  "anchoring",
  "ledger",
  "standing",
  "attestations",
  // M23: the daily CC0 export is a stage of the pipeline like any other, and
  // the page counts whatever it is handed — nothing here or in the page pins
  // how many stages there are.
  "mirror export",
];

function stage(name: string, state: Stage["state"]): Stage {
  return {
    stage: name,
    state,
    last: `${name} last line`,
    rule: `the rule for ${name}`,
    evidence: [{ label: `${name} evidence`, href: "/status" }],
  };
}

const EXERCISED: readonly Exercised[] = [
  {
    stage: "submit and archive",
    last: "2026-09-10 13:52 UTC",
    evidence: [{ label: "nmk_4d7c5efb…8663", href: `/entries/${ENTRY_ID}` }],
  },
  {
    stage: "registration, DNS check",
    last: "2026-09-10 13:51 UTC",
    evidence: [{ label: "fixture-e", href: "/operators/fixture-e" }],
  },
  {
    stage: "read receipts",
    last: "counter 34 · 13:06 UTC",
    evidence: [{ label: "a read", href: `/read/${ENTRY_ID}` }],
  },
  {
    stage: "sync receipts",
    last: "counter 33 · 13:06 UTC",
    evidence: [{ label: "a sync", href: "/sync?from=43" }],
  },
  {
    stage: "payouts",
    last: "never · mock adapter",
    evidence: [
      { label: "every operator below PAYOUT_MINIMUM_MICROS", href: "" },
    ],
  },
];

const HEALTHY_COUNTER: Counter = {
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

const HEALTHY: StatusData = {
  asOf: "2026-09-10T14:05:07.000Z",
  counters: HEALTHY_COUNTER,
  stages: STAGE_NAMES.map((name) => stage(name, "ok")),
  exercised: EXERCISED,
};

/** One of each light, so the four badge classes can be told apart. */
const DEGRADED: StatusData = {
  asOf: "2026-09-10T13:42:04.000Z",
  counters: {
    ...HEALTHY_COUNTER,
    lastSweepAge: "23 min ago",
    lastSweepAt: "2026-09-10T13:42:04.000Z",
    stagesOk: 10,
    stagesFailing: 1,
    stagesAttention: 2,
    unsealedEvents: 3,
  },
  stages: STAGE_NAMES.map((name) => {
    if (name === "witnessing") return stage(name, "failing");
    if (name === "sweep timer" || name === "ledger") {
      return stage(name, "attention");
    }
    if (name === "staleness") return stage(name, "idle");
    return stage(name, "ok");
  }),
  exercised: EXERCISED,
};

describe("renderStatus", () => {
  const page = renderStatus(statusCtx, HEALTHY);

  it("shows the four counters, worded by the rules and not by the page", () => {
    expect(page).toContain('<div class="counter-label">last sweep</div>');
    expect(page).toContain('<div class="counter-label">stages</div>');
    expect(page).toContain('<div class="counter-label">sealed head</div>');
    expect(page).toContain('<div class="counter-label">witnessed</div>');
    expect(page).toContain("2 min ago");
    expect(page).toContain("14:05:07 UTC");
    expect(page).toContain("alarm");
    expect(flat(page)).toContain(`every ${SWEEP_INTERVAL_MINUTES} min`);
    expect(page).toContain("all ok");
    expect(flat(page)).toContain("seal 11 · 0 unsealed events");
    expect(page).toContain("mock witnesses on demo");
  });

  it("dates itself by the sweep run and points at the JSON", () => {
    expect(flat(page)).toContain("as of the sweep run at 2026-09-10 14:05:07 UTC");
    expect(page).toContain('<a href="/status" class="mono">GET /status</a>');
    expect(flat(page)).toContain("GET /status</a> answers this table as JSON");
  });

  it("renders every stage it is handed, with the rule and the evidence beside each", () => {
    for (const name of STAGE_NAMES) {
      expect(page, `${name} has no row`).toContain(`<td>${name}</td>`);
      expect(page, `${name} shows no rule`).toContain(`the rule for ${name}`);
      expect(flat(page), `${name} shows no evidence`).toContain(
        `${name} evidence</a>`,
      );
    }
    expect(page).toContain("Pipeline, stage by stage");
  });

  it("gives each of the four states its own badge class", () => {
    const degraded = renderStatus(statusCtx, DEGRADED);
    expect(degraded).toContain('<span class="badge s-verified">ok</span>');
    expect(degraded).toContain('<span class="badge b-stale">attention</span>');
    expect(degraded).toContain('<span class="badge s-rejected">failing</span>');
    expect(degraded).toContain('<span class="badge s-other">idle</span>');
  });

  it("shows the exercised table and the legend", () => {
    expect(page).toContain("Exercised, not probed");
    for (const each of EXERCISED) {
      expect(page, `${each.stage} is not exercised`).toContain(
        `<td>${each.stage}</td>`,
      );
      expect(page, `${each.stage} has no last line`).toContain(each.last);
    }
    // The payout row names no path, so its label is text and never an empty link.
    expect(page).toContain("every operator below PAYOUT_MINIMUM_MICROS");
    expect(page).not.toContain('href=""');

    expect(page).toContain("How a light is decided");
    expect(page).toContain("STATUS_FAILING_AFTER_MINUTES");
    expect(flat(page)).toContain(
      `curl -s ${ctx.origin}/status | jq '.stages[] | select(.state != "ok")'`,
    );
  });

  it("draws the band only when a stage is failing or wants attention", () => {
    expect(page).not.toContain('class="alert"');
    const degraded = renderStatus(statusCtx, DEGRADED);
    expect(degraded).toContain('<div class="alert">');
    expect(degraded).toContain(
      '<span class="alert-title">2 stages need attention, 1 is failing</span>',
    );
    // And the sentence names them, in the rules module's own words.
    expect(flat(degraded)).toContain("Witnessing is failing");
    expect(flat(degraded)).toContain("sweep timer and ledger need attention");
    expect(flat(degraded)).toContain("The other 10 stages hold.");
  });

  it("carries no script and no inline style", () => {
    for (const document of [page, renderStatus(statusCtx, DEGRADED)]) {
      expect(document).not.toContain("<script");
      expect(document).not.toContain(' style="');
    }
  });
});

// ---------------------------------------------------------------------------
// The nav
// ---------------------------------------------------------------------------

describe("the nav", () => {
  it("carries both pages, after Genesis and before the paper", () => {
    const page = renderStatus(statusCtx, HEALTHY);
    const genesis = page.indexOf('href="/genesis"');
    const how = page.indexOf('href="/how-it-works"');
    const status = page.indexOf('href="/status"');
    const paper = page.indexOf("WHITEPAPER.md");
    expect(genesis).toBeGreaterThan(-1);
    expect(how).toBeGreaterThan(genesis);
    expect(status).toBeGreaterThan(how);
    expect(paper).toBeGreaterThan(status);
    expect(page).toContain("How it works");
  });

  it("marks each of them active on its own path and nowhere else", () => {
    const how = renderHowItWorks(ctx, EMPTY);
    expect(how).toContain('<a class="nav nav-active" href="/how-it-works">');
    expect(how).not.toContain('<a class="nav nav-active" href="/status">');

    const status = renderStatus(statusCtx, HEALTHY);
    expect(status).toContain('<a class="nav nav-active" href="/status">');
    expect(status).not.toContain(
      '<a class="nav nav-active" href="/how-it-works">',
    );
  });
});

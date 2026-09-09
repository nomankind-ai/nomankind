/**
 * The apex landing page (decisions D-021, D-062 as amended): what nomankind is,
 * for someone who arrived at nomankind.ai and has never heard of it.
 *
 * The one page that is NOT in the shared layout. It has no header nav and no
 * environment badge, because it is not an instrument panel — it is the front
 * door, and the app lives at app.nomankind.ai. So this returns a whole document
 * of its own, built the same CSP-safe way: no inline style attribute, no script,
 * one stylesheet from this Worker and one from Google Fonts.
 *
 * Direction D: the dark ground, the proof path drawn beside the headline rather
 * than described under it, and the seal chain shown live — the newest seals off
 * the log itself, sliding through a band under the hero, with the three numerals
 * beneath it read from the same store. A front door for a log has to be able to
 * show that the log is moving, and a hard-coded number would be a claim rather
 * than a reading. So this page takes a `LandingData` and prints it; the route
 * (src/worker/pages.ts) does the reading, and nothing here derives anything.
 *
 * The diagram is inline SVG, so it needs no script: the dashed feed lines move
 * on a keyframed stroke-dashoffset, the three amber witness dots pulse, and the
 * band slides on a translateX keyframe over the rows written twice, so the loop
 * has no seam. All three stop dead under prefers-reduced-motion, and the page
 * says exactly the same thing standing still. Its own visual system, sharing no
 * class name with the app stylesheet, which is why LANDING_CSS below is served
 * separately at /static/landing.css rather than appended to app.css.
 */

import { fmtInstant, html, shortHash, type Safe } from "../html.js";
import type { LandingData, PageContext } from "../types.js";

/** Where the top bar points. External every one of them: the record lives in git. */
const PAPER_URL =
  "https://github.com/nomankind-ai/nomankind/blob/main/paper/WHITEPAPER.md";
const CODE_URL = "https://github.com/nomankind-ai/nomankind";
const LOG_URL = "https://github.com/nomankind-ai/log";
const REGISTRY_URL = "https://1f916.org";
const APP_URL = "https://app.nomankind.ai";
const DEMO_URL = "https://demo.nomankind.ai";

/**
 * The proof pipeline, drawn. Source, snapshot, three operators, the teal seal
 * with its witnesses, the learner that syncs last. Authored on a 760×300 viewBox
 * and scaled by the stylesheet, so the drawing is the same shape at every width.
 */
const PIPELINE = html`<svg
            class="pipeline"
            viewBox="0 0 760 300"
            fill="none"
            role="img"
            aria-label="A cited source is snapshotted and hashed, checked and signed by three independent operators, sealed every five minutes and countersigned by independent witnesses, and only then read by a learner that syncs from its last sealed position."
          >
            <line x1="96" y1="120" x2="190" y2="120" stroke="#7fd1c4" stroke-width="2" class="flow"></line>
            <line x1="286" y1="120" x2="380" y2="50" stroke="#7fd1c4" stroke-width="2" class="flow"></line>
            <line x1="286" y1="120" x2="380" y2="120" stroke="#7fd1c4" stroke-width="2" class="flow"></line>
            <line x1="286" y1="120" x2="380" y2="190" stroke="#7fd1c4" stroke-width="2" class="flow"></line>
            <line x1="476" y1="50" x2="570" y2="120" stroke="#7fd1c4" stroke-width="2" class="flow"></line>
            <line x1="476" y1="120" x2="570" y2="120" stroke="#7fd1c4" stroke-width="2" class="flow"></line>
            <line x1="476" y1="190" x2="570" y2="120" stroke="#7fd1c4" stroke-width="2" class="flow"></line>
            <line x1="666" y1="120" x2="700" y2="120" stroke="#e0b458" stroke-width="2" class="flow"></line>

            <rect x="0" y="86" width="96" height="68" stroke="#3a424c" stroke-width="1.5" fill="#0b0d10"></rect>
            <text class="node-name" x="48" y="116" text-anchor="middle" font-size="22" fill="#ece9e2">Source</text>
            <text class="node-note" x="48" y="138" text-anchor="middle" font-size="10" fill="#7f8794">cited page</text>

            <rect x="190" y="86" width="96" height="68" stroke="#3a424c" stroke-width="1.5" fill="#0b0d10"></rect>
            <text class="node-name" x="238" y="116" text-anchor="middle" font-size="22" fill="#ece9e2">Snapshot</text>
            <text class="node-note" x="238" y="138" text-anchor="middle" font-size="10" fill="#7f8794">hashed, frozen</text>

            <rect x="380" y="26" width="96" height="48" stroke="#3a424c" stroke-width="1.5" fill="#0b0d10"></rect>
            <text class="node-name" x="428" y="56" text-anchor="middle" font-size="19" fill="#ece9e2">Operator A</text>
            <rect x="380" y="96" width="96" height="48" stroke="#3a424c" stroke-width="1.5" fill="#0b0d10"></rect>
            <text class="node-name" x="428" y="126" text-anchor="middle" font-size="19" fill="#ece9e2">Operator B</text>
            <rect x="380" y="166" width="96" height="48" stroke="#7fd1c4" stroke-width="1.5" fill="#0b0d10"></rect>
            <text class="node-name" x="428" y="196" text-anchor="middle" font-size="19" fill="#ece9e2">Operator C</text>
            <text class="node-note" x="428" y="246" text-anchor="middle" font-size="10" fill="#7f8794">three independent · fetch, test, sign</text>

            <rect x="570" y="86" width="96" height="68" stroke="#7fd1c4" stroke-width="1.5" fill="#7fd1c4"></rect>
            <text class="node-name" x="618" y="116" text-anchor="middle" font-size="22" fill="#0b0d10">Seal</text>
            <text class="node-note" x="618" y="138" text-anchor="middle" font-size="10" fill="#0b0d10">every 5 min</text>
            <circle cx="598" cy="190" r="5" fill="#e0b458" class="pulse"></circle>
            <circle cx="618" cy="190" r="5" fill="#e0b458" class="pulse"></circle>
            <circle cx="638" cy="190" r="5" fill="#e0b458" class="pulse"></circle>
            <text class="node-note" x="618" y="266" text-anchor="middle" font-size="10" fill="#7f8794">witnesses countersign</text>

            <rect x="700" y="86" width="60" height="68" stroke="#e0b458" stroke-width="2" fill="#0b0d10"></rect>
            <text class="node-name" x="730" y="116" text-anchor="middle" font-size="20" fill="#ece9e2">Learner</text>
            <text class="node-note" x="730" y="138" text-anchor="middle" font-size="10" fill="#7f8794">syncs last</text>
          </svg>`;

/** The three cards under the numerals: the use case, the provenance, the truth. */
const CARDS: readonly {
  readonly label: string;
  readonly head: string;
  readonly body: string;
}[] = [
  {
    label: "PRIMARY USE · CONTINUAL LEARNING",
    head: "Pull every change since your last sync, sealed and in order.",
    body:
      "Two models syncing from the same position take in the same sequence and can prove it. Overturned facts arrive as explicit unlearn signals.",
  },
  {
    label: "PROVENANCE, PROVEN",
    head: "The chain of custody travels with the fact.",
    body:
      "Source hash, three independent signatures, seal time, last-confirmed date, and every dispute since. Anyone can recheck it offline.",
  },
  {
    label: "TRUTH, WHERE A TEST CAN REACH",
    head: "Measured, not just cited.",
    body:
      "Prices, rate limits, deprecations, model behavior: where a claim can be measured, validators run the test themselves and record their own receipts.",
  },
];

/** The five values, numbered. The paper's goals list, in its words. */
const VALUES: readonly { readonly head: string; readonly body: string }[] = [
  {
    head: "Owned by no lab.",
    body:
      "No model provider funds, runs, or validates the record. The maintainer runs the pipes and never the judgment.",
  },
  {
    head: "Facts, never opinions.",
    body:
      "An entry states what a cited source said or what a reproducible transcript shows. No rankings, no scores, no characterizations.",
  },
  {
    head: "Rewards for being right, never for being busy.",
    body:
      "Contributors are paid when the facts they backed are read and survive. Errors are clawed back and attributed, forever.",
  },
  {
    head: "Checkable by anyone, offline.",
    body:
      "Every entry is hashed, signed, and sealed into a witnessed log. Trust is not required; the proof travels with the record.",
  },
  {
    head: "Exit is the only real check.",
    body:
      "The code is open, the data is public domain, and the whole log is forkable. If nomankind breaks its own rules, anyone leaves with the entire record.",
  },
];

/**
 * The wall-clock part of a seal's instant, `04:49:44Z`, off the shared
 * formatter. The band is one line of mono in a moving strip and the day is the
 * same for every cell in it, so the date would be eight characters of noise; the
 * full instant is on the seal's own page. Formatting, not derivation: the value
 * printed is the `sealed_at` the kernel sealed.
 */
function clockOf(iso: string): string {
  const text = fmtInstant(iso);
  const space = text.indexOf(" ");
  return space === -1 ? text : text.slice(space + 1);
}

/**
 * The seal chain's cells, newest last, exactly as the log handed them over.
 *
 * The hash is shown short with the whole of it in the `title`, because a hash a
 * reader cannot copy in full is a hash they cannot check, and the seq carries
 * how many events that seal covers — the size the kernel sealed, not a count
 * taken here.
 */
function bandCells(seals: LandingData["seals"]): Safe[] {
  return seals.map(
    (seal) => html`<div class="band-cell">
            <span class="band-seq" title="${seal.events} events">#${seal.seq}</span>
            <span title="${seal.hash}">${shortHash(seal.hash)}</span>
            <span class="band-time">${clockOf(seal.sealedAt)}</span>
            ${seal.witnessed
              ? html`<span class="band-witnessed">witnessed</span>`
              : html`<span class="band-pending">pending</span>`}
          </div>`,
  );
}

export function renderLanding(ctx: PageContext, data: LandingData): string {
  void ctx;
  const empty = data.seals.length === 0;
  // Written twice, so translateX(-50%) lands the strip exactly where it started
  // and the loop has no seam. With nothing sealed there is nothing to loop, so
  // the band holds one cell and the animation is off rather than sliding a
  // placeholder past the reader.
  const cells = empty
    ? html`<div class="band-cell"><span class="band-seq">no seal yet</span></div>`
    : html`${bandCells(data.seals)}${bandCells(data.seals)}`;

  return html`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>nomankind</title>
    <meta
      name="description"
      content="A public log of small cited facts about the AI ecosystem, built to be learned from. Every fact a model takes in arrives with its provenance proven, and with proof of truth wherever a test can reach."
    />
    <link
      rel="stylesheet"
      href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&amp;family=Manrope:wght@400;500;600&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap"
    />
    <link rel="stylesheet" href="/static/landing.css" />
  </head>
  <body class="landing">
    <div class="sheet">
      <header class="topbar row">
        <span class="wordmark mono">NOMANKIND</span>
        <nav class="topnav">
          <a href="${PAPER_URL}" rel="noopener">Whitepaper</a>
          <a href="${CODE_URL}" rel="noopener">Code</a>
          <a href="${LOG_URL}" rel="noopener">Log mirror</a>
          <a href="${REGISTRY_URL}" rel="noopener">Built on 1F916</a>
        </nav>
        <div class="topcta">
          <a class="btn-primary" href="${APP_URL}">Open the app</a>
          <a class="btn-ghost" href="${DEMO_URL}">Try the demo</a>
        </div>
      </header>

      <section class="hero row">
        <div class="hero-copy">
          <p class="eyebrow eyebrow-teal">
            THE SEALED FEED FOR MODELS THAT KEEP LEARNING
          </p>
          <h1 class="display hero-title">
            Proof first.<br /><em class="hero-turn">Use second.</em>
          </h1>
          <p class="hero-sub">
            A public log of small cited facts about the AI ecosystem, built to be
            learned from. Every fact a model takes in arrives with its provenance
            proven, and with proof of truth wherever a test can reach.
          </p>
        </div>
        <div class="diagram-panel">
          ${PIPELINE}
          <div class="pipeline-legend mono">
            <span>CAPTURED → HASHED → CHECKED ×3 → SEALED → WITNESSED → DATED → LEARNED</span>
            <span>A LEARNER SYNCS FROM ITS LAST SEALED POSITION</span>
          </div>
        </div>
      </section>

      <section class="band" aria-label="The newest seals in the log">
        <div class="band-label">
          <span class="band-dot"></span>
          <span class="band-label-text mono">SEAL CHAIN · LIVE</span>
        </div>
        <div class="band-track">
          <div class="${empty ? "band-inner band-still mono" : "band-inner mono"}">
            ${cells}
          </div>
        </div>
      </section>

      <section class="numerals row">
        <div class="numeral">
          <p class="numeral-label mono">SEALS</p>
          <p class="display numeral-value">${data.sealCount}</p>
          <p class="numeral-note mono">one every five minutes, each countersigned</p>
        </div>
        <div class="numeral">
          <p class="numeral-label mono">INDEPENDENT WITNESSES</p>
          <p class="display numeral-value">${data.witnesses}</p>
          <p class="numeral-note mono">none under a model provider</p>
        </div>
        <div class="numeral">
          <p class="numeral-label mono">VERIFIED FACTS</p>
          <p class="display numeral-value">${data.verified}</p>
          <p class="numeral-note mono">in the sealed log</p>
        </div>
      </section>

      <section class="cards row">
        ${CARDS.map(
          (card) => html`<article class="card">
          <p class="eyebrow eyebrow-label eyebrow-teal">${card.label}</p>
          <h2 class="display card-head">${card.head}</h2>
          <p class="card-body">${card.body}</p>
        </article>`,
        )}
      </section>

      <section class="duo">
        <div class="duo-col row">
          <p class="eyebrow eyebrow-teal">BUILT FOR MODELS THAT TRAIN FROM IT</p>
          <h2 class="display duo-title">
            Models learn from the world, and every fact they take in came from
            somewhere. Today that somewhere is worked out afterwards, if at all.
          </h2>
          <p class="duo-body">
            nomankind turns the order around. Before a fact can be learned from,
            its source is captured and hashed, three independent operators check
            it and sign, and the record is sealed with a timestamp. A continual
            learner then pulls every change since its last sync as a sealed delta
            stream, in the exact order it was sealed. Each fact carries its
            evidence and a last-confirmed date, so a learner can weight it, hold
            it, or skip it. A frozen model reads one signed fact on wake, with its
            receipt and no injection surface.
          </p>
        </div>
        <div class="duo-col row">
          <p class="eyebrow eyebrow-amber">PROVENANCE OF WHAT A MODEL LEARNED</p>
          <h2 class="display duo-title">
            Sources rot. Labs edit their own pages quietly. A model that keeps
            learning has nowhere neutral to look.
          </h2>
          <p class="duo-body">
            Every fact a learner takes from the stream arrives with its chain of
            custody complete: source hash, three independent signatures, seal
            time, reproduction counts where a test exists, and every dispute
            since. Even if the original page is later edited or destroyed, the
            sealed, dated record of what it said still stands, and anyone can
            check it offline with two files and one script. A model can say which
            belief came from which page, and independent operators can certify in
            public that its beliefs still match the record.
          </p>
        </div>
      </section>

      <section class="values row">
        <p class="eyebrow eyebrow-dim">WHAT WE HOLD TO</p>
        <div class="values-grid">
          ${VALUES.map(
            (value, index) => html`<div class="value">
            <p class="value-index mono">0${index + 1}</p>
            <p class="display value-head">${value.head}</p>
            <p class="value-body">${value.body}</p>
          </div>`,
          )}
        </div>
      </section>

      <section class="tiers">
        <div class="tiers-copy">
          <p class="eyebrow">TWO TIERS OF EVIDENCE</p>
          <h2 class="display tiers-title">
            Provenance is the floor.
            <em>Truth, wherever a test can reach.</em>
          </h2>
        </div>
        <p class="tiers-body">
          Verified means three independent operators confirmed that the source
          says what the entry says. For a fact that rests only on a cited page,
          that is provenance, and the log says so. Where a claim can be measured,
          a metered call, a probe to a limit, a reproduced prompt, the submitter
          freezes the test and validators run it themselves under a published
          rule, each recording its own receipt. The entry moves past "a source
          said it" toward "this was observed to hold", and its tier tells a
          learner which it is holding.
        </p>
      </section>

      <footer class="landing-footer row mono">
        <span>CODE APACHE-2.0 · DATA CC0 · TRAINING ON THE DATA IS FREE</span>
        <span>NOMANKIND.AI</span>
      </footer>
    </div>
  </body>
</html>
`.markup;
}

/**
 * The landing page's whole stylesheet, served at /static/landing.css.
 *
 * Separate from APP_CSS on purpose: the landing is its own visual system
 * (D-021, D-062) and shares not one class with the instrument panel, so the two
 * sheets can move independently and neither builder edits the other's rules.
 *
 * Direction D's ground: near-black panels, one teal accent for proof and one
 * amber for what the outside world has not finished yet. Instrument Serif for
 * display, Manrope for body, JetBrains Mono for the eyebrows, the band and the
 * labels, each with a real fallback stack, because a page whose meaning depends
 * on a font that failed to load is a page that failed.
 *
 * The artboard is drawn at one width (1440 px); everything below that is fluid.
 * The content column stops at 1440 px, the side padding is 48 px and 24 px on a
 * phone, the display sizes step down with clamp() so no headline breaks a word,
 * the drawing scales on its viewBox, the band scrolls its own strip inside a
 * clipped track rather than widening the page, and every grid stacks under
 * 900 px.
 */
export const LANDING_CSS = `
/* ---------------------------------------------------------------------------
   The apex landing page (D-062, direction D). Its own namespace: body.landing.
   --------------------------------------------------------------------------- */

.landing {
  --ground: #0b0d10;
  --panel: #0f1216;
  --rule: #1f242b;
  --rule-2: #2c333c;
  --edge: #3a424c;
  --text: #ece9e2;
  --muted: #aab2bd;
  --dim: #7f8794;
  --teal: #7fd1c4;
  --amber: #e0b458;
  --display: "Instrument Serif", Georgia, "Times New Roman", serif;
  --body: "Manrope", "Helvetica Neue", Arial, sans-serif;
  --mono: "JetBrains Mono", Menlo, Consolas, monospace;
  --pad: 48px;
  margin: 0;
  background: var(--ground);
  color: var(--text);
  font-family: var(--body);
  font-weight: 400;
  -webkit-font-smoothing: antialiased;
  overflow-x: hidden;
}

.landing a {
  color: inherit;
  text-decoration: none;
}

.landing a:hover {
  color: var(--teal);
}

.display {
  font-family: var(--display);
  font-weight: 400;
  margin: 0;
}

.mono {
  font-family: var(--mono);
}

.eyebrow {
  font-family: var(--mono);
  font-weight: 400;
  font-size: 12px;
  letter-spacing: 0.3em;
  line-height: 1.5;
  margin: 0;
}

.eyebrow-label {
  font-size: 11px;
  letter-spacing: 0.2em;
}

.eyebrow-teal {
  color: var(--teal);
}

.eyebrow-amber {
  color: var(--amber);
}

.eyebrow-dim {
  color: var(--dim);
}

/* One centred column, the artboard's width at most, with the artboard's air. */

.sheet {
  max-width: 1440px;
  margin: 0 auto;
}

.row {
  box-sizing: border-box;
  padding-left: var(--pad);
  padding-right: var(--pad);
}

/* --- the top bar ---------------------------------------------------------- */

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 20px;
  padding-top: 22px;
  padding-bottom: 22px;
  border-bottom: 1px solid var(--rule);
}

.wordmark {
  font-size: 13px;
  letter-spacing: 0.32em;
}

.topnav {
  display: flex;
  flex-wrap: wrap;
  gap: 28px;
  font-size: 14px;
  color: var(--muted);
}

.topcta {
  display: flex;
  gap: 10px;
}

/* Scoped under .landing so these out-specify the "a { color: inherit }" rule
   above: a filled button that inherited the body colour is a teal block with an
   invisible label. */
.landing .btn-primary,
.landing .btn-ghost {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  box-sizing: border-box;
  height: 44px;
  padding: 0 20px;
  font-size: 14px;
  white-space: nowrap;
}

.landing .btn-primary {
  background: var(--teal);
  color: var(--ground);
  font-weight: 600;
  transition: opacity 0.25s ease;
}

.landing .btn-primary:hover {
  color: var(--ground);
  opacity: 0.82;
}

.landing .btn-ghost {
  border: 1px solid var(--edge);
  color: var(--text);
  font-weight: 500;
  transition: border-color 0.25s ease, color 0.25s ease;
}

.landing .btn-ghost:hover {
  border-color: var(--teal);
  color: var(--teal);
}

/* --- the hero: the copy, and the drawing beside it ------------------------ */

.hero {
  display: grid;
  grid-template-columns: 5fr 7fr;
  gap: 40px;
  align-items: center;
  padding-top: 80px;
  padding-bottom: 48px;
}

.hero-copy {
  display: flex;
  flex-direction: column;
  gap: 26px;
  min-width: 0;
}

/* clamp() rather than one size: at 1440 the artboard's 124px, and small enough
   on a phone that not one word of it has to break. */
.hero-title {
  font-size: clamp(44px, 8.4vw, 124px);
  line-height: 0.92;
  letter-spacing: -0.02em;
  text-wrap: balance;
}

.hero-turn {
  font-style: italic;
  color: var(--teal);
}

.hero-sub {
  margin: 0;
  max-width: 520px;
  font-size: clamp(17px, 1.5vw, 21px);
  line-height: 1.5;
  color: var(--muted);
  text-wrap: pretty;
}

.diagram-panel {
  box-sizing: border-box;
  min-width: 0;
  border: 1px solid var(--rule-2);
  background: var(--panel);
  padding: 32px 24px 20px 24px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

/* The drawing keeps its shape and scales with the panel: one viewBox, no width
   attribute, so there is nothing to overflow at any width. */
.pipeline {
  display: block;
  width: 100%;
  height: auto;
}

.node-name {
  font-family: var(--display);
}

.node-note {
  font-family: var(--mono);
}

.pipeline-legend {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 8px 20px;
  font-size: 10px;
  letter-spacing: 0.2em;
  line-height: 1.6;
  color: var(--dim);
  border-top: 1px solid var(--rule);
  padding-top: 12px;
}

/* --- the seal chain band --------------------------------------------------
   The one live thing on the page: the newest seals off the log, sliding. The
   track is clipped and the strip is sized to its content, so the strip is the
   only thing that is wider than the viewport and the page never scrolls
   sideways because of it.
   ------------------------------------------------------------------------- */

.band {
  display: flex;
  align-items: stretch;
  background: var(--panel);
  border-top: 1px solid var(--rule);
  border-bottom: 1px solid var(--rule);
}

.band-label {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
  padding: 18px 24px;
  border-right: 1px solid var(--rule);
}

.band-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--teal);
}

.band-label-text {
  font-size: 11px;
  letter-spacing: 0.2em;
  color: var(--teal);
  white-space: nowrap;
}

.band-track {
  flex-grow: 1;
  min-width: 0;
  overflow: hidden;
}

.band-inner {
  display: flex;
  width: max-content;
  font-size: 12px;
  animation: slide 40s linear infinite;
}

/* Nothing sealed yet: one cell, and nothing to loop. */
.band-still {
  animation: none;
}

.band-cell {
  display: flex;
  align-items: baseline;
  gap: 14px;
  padding: 18px 24px;
  border-right: 1px solid var(--rule);
  white-space: nowrap;
}

.band-seq,
.band-time {
  color: var(--dim);
}

.band-witnessed {
  color: var(--teal);
}

.band-pending {
  color: var(--amber);
}

/* --- the three numerals --------------------------------------------------- */

.numerals {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 24px;
  padding-top: 56px;
  padding-bottom: 56px;
}

.numeral {
  display: flex;
  flex-direction: column;
  gap: 6px;
  border-top: 1px solid var(--rule-2);
  padding-top: 16px;
}

.numeral-label {
  margin: 0;
  font-size: 11px;
  letter-spacing: 0.2em;
  color: var(--dim);
}

.numeral-value {
  font-size: clamp(56px, 6.2vw, 88px);
  line-height: 1;
}

.numeral-note {
  margin: 0;
  font-size: 11px;
  line-height: 1.5;
  color: var(--teal);
}

/* --- the three cards ------------------------------------------------------ */

.cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 24px;
  padding-bottom: 56px;
}

.card {
  display: flex;
  flex-direction: column;
  gap: 8px;
  border-top: 2px solid var(--teal);
  padding-top: 14px;
}

.card-head {
  font-size: clamp(24px, 2.1vw, 30px);
  line-height: 1.1;
}

.card-body {
  margin: 0;
  font-size: 14px;
  line-height: 1.55;
  color: var(--muted);
  text-wrap: pretty;
}

/* --- the two columns ------------------------------------------------------ */

.duo {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  border-top: 1px solid var(--rule);
  border-bottom: 1px solid var(--rule);
}

.duo-col {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding-top: 64px;
  padding-bottom: 64px;
}

.duo-col:first-child {
  border-right: 1px solid var(--rule);
}

.duo-title {
  font-size: clamp(30px, 3.1vw, 44px);
  line-height: 1.08;
}

.duo-body {
  margin: 0;
  font-size: clamp(16px, 1.3vw, 17px);
  line-height: 1.6;
  color: var(--muted);
  text-wrap: pretty;
}

/* --- the five values ------------------------------------------------------ */

.values {
  display: flex;
  flex-direction: column;
  gap: 36px;
  padding-top: 72px;
  padding-bottom: 72px;
}

.values-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 24px;
}

.value {
  display: flex;
  flex-direction: column;
  gap: 10px;
  border-top: 2px solid var(--teal);
  padding-top: 18px;
}

.value-index {
  margin: 0;
  font-size: 11px;
  color: var(--dim);
}

.value-head {
  font-size: clamp(24px, 2vw, 30px);
  line-height: 1.05;
}

.value-body {
  margin: 0;
  font-size: 14px;
  line-height: 1.55;
  color: var(--muted);
  text-wrap: pretty;
}

/* --- the two tiers, on the accent ----------------------------------------- */

.tiers {
  box-sizing: border-box;
  margin: 0 var(--pad) 72px var(--pad);
  padding: 56px;
  background: var(--teal);
  color: var(--ground);
  display: grid;
  grid-template-columns: 8fr 4fr;
  gap: 24px;
  align-items: end;
}

.tiers-copy {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.tiers-title {
  font-size: clamp(36px, 4.4vw, 64px);
  line-height: 0.98;
  letter-spacing: -0.01em;
}

.tiers-title em {
  font-style: italic;
}

.tiers-body {
  margin: 0;
  font-size: 15px;
  line-height: 1.55;
  text-wrap: pretty;
}

/* --- the footer ----------------------------------------------------------- */

.landing-footer {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 10px 24px;
  padding-top: 22px;
  padding-bottom: 22px;
  border-top: 1px solid var(--rule);
  font-size: 11px;
  letter-spacing: 0.2em;
  line-height: 1.6;
  color: var(--dim);
}

/* --- motion --------------------------------------------------------------
   The whole of it, and there is no script: the feed lines are dashed strokes
   whose offset moves, the witness dots breathe, and the seal band slides over
   its rows written twice. All three stop under prefers-reduced-motion, and the
   page reads exactly the same standing still.
   ------------------------------------------------------------------------- */

@keyframes flow {
  to { stroke-dashoffset: -40; }
}

.flow {
  stroke-dasharray: 8 12;
  animation: flow 1.6s linear infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 0.35; }
  50% { opacity: 1; }
}

.pulse {
  animation: pulse 2.4s ease-in-out infinite;
}

@keyframes slide {
  from { transform: translateX(0); }
  to { transform: translateX(-50%); }
}

@media (prefers-reduced-motion: reduce) {
  .landing *,
  .landing *::before,
  .landing *::after {
    animation: none !important;
    transition: none !important;
  }
  .flow {
    stroke-dasharray: 8 12;
  }
  .pulse {
    opacity: 1;
  }
}

/* --- under 1200 px: the five values go two-up ----------------------------- */

@media (max-width: 1200px) {
  .values-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

/* --- under 900 px: every grid stacks ------------------------------------- */

@media (max-width: 900px) {
  .hero,
  .numerals,
  .cards,
  .duo,
  .values-grid,
  .tiers {
    grid-template-columns: minmax(0, 1fr);
  }
  .hero {
    padding-top: 56px;
    gap: 32px;
  }
  .duo-col:first-child {
    border-right: 0;
    border-bottom: 1px solid var(--rule);
  }
  .duo-col {
    padding-top: 48px;
    padding-bottom: 48px;
  }
  .topbar {
    gap: 16px;
  }
  .topnav {
    gap: 20px;
    font-size: 13px;
  }
  .diagram-panel {
    padding: 24px 20px 20px 20px;
  }
  .tiers {
    padding: 40px;
    align-items: start;
  }
}

/* --- under 700 px: less side air, tighter labels -------------------------- */

@media (max-width: 700px) {
  .landing {
    --pad: 24px;
  }
  .hero {
    padding-top: 44px;
    padding-bottom: 32px;
  }
  .numerals {
    padding-top: 40px;
    padding-bottom: 40px;
  }
  .cards {
    padding-bottom: 44px;
  }
  .values {
    padding-top: 48px;
    padding-bottom: 48px;
    gap: 28px;
  }
  .tiers {
    margin-bottom: 48px;
    padding: 28px;
  }
  .band-label,
  .band-cell {
    padding: 14px 16px;
  }
  .pipeline-legend,
  .landing-footer {
    font-size: 10px;
    letter-spacing: 0.12em;
  }
}
`;

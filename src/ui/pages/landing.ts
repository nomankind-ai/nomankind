/**
 * The apex landing page (decisions D-021, D-062): what nomankind is, for someone
 * who arrived at nomankind.ai and has never heard of it.
 *
 * The one page that is NOT in the shared layout. It has no header nav and no
 * environment badge, because it is not an instrument panel — it is the front
 * door, and the app lives at app.nomankind.ai. So this returns a whole document
 * of its own, built the same CSP-safe way: no inline style attribute, no script,
 * one stylesheet from this Worker and one from Google Fonts.
 *
 * Version three (D-062, direction C) draws the proof path rather than describing
 * it: the pipeline from the cited source through the snapshot, the three
 * independent operators, the seal and the witnesses, to the learner that syncs
 * last. The copy is written around the primary use case — feeding models that
 * keep learning — with provenance proven on every fact and proof of truth
 * wherever a test can reach.
 *
 * The diagram is inline SVG, so it needs no script: the dashed feed lines move
 * on a keyframed stroke-dashoffset and the three amber dots pulse, and both stop
 * dead under prefers-reduced-motion. Its own visual system, sharing no class name
 * with the app stylesheet, which is why LANDING_CSS below is served separately at
 * /static/landing.css rather than appended to app.css.
 */

import { html } from "../html.js";
import type { PageContext } from "../types.js";

/** Where the top bar points. External every one of them: the record lives in git. */
const PAPER_URL =
  "https://github.com/nomankind-ai/nomankind/blob/main/paper/WHITEPAPER.md";
const CODE_URL = "https://github.com/nomankind-ai/nomankind";
const LOG_URL = "https://github.com/nomankind-ai/log";
const REGISTRY_URL = "https://1f916.org";
const APP_URL = "https://app.nomankind.ai";
const DEMO_URL = "https://demo.nomankind.ai";

/**
 * The proof pipeline, drawn. Source, snapshot, three operators, the seal with its
 * witnesses, the learner that syncs last. Authored on a 1310×300 viewBox and
 * scaled by the stylesheet, so the drawing is the same shape at every width.
 */
const PIPELINE = html`<svg
          class="pipeline"
          viewBox="0 0 1310 300"
          fill="none"
          role="img"
          aria-label="A cited source is snapshotted and hashed, checked and signed by three independent operators, sealed every five minutes and countersigned by independent witnesses, and only then read by a learner that syncs from its last sealed position."
        >
          <line x1="150" y1="120" x2="330" y2="120" stroke="#b07a1e" stroke-width="2" class="flow"></line>
          <line x1="470" y1="120" x2="640" y2="60" stroke="#b07a1e" stroke-width="2" class="flow"></line>
          <line x1="470" y1="120" x2="640" y2="120" stroke="#b07a1e" stroke-width="2" class="flow"></line>
          <line x1="470" y1="120" x2="640" y2="180" stroke="#b07a1e" stroke-width="2" class="flow"></line>
          <line x1="780" y1="60" x2="940" y2="120" stroke="#b07a1e" stroke-width="2" class="flow"></line>
          <line x1="780" y1="120" x2="940" y2="120" stroke="#b07a1e" stroke-width="2" class="flow"></line>
          <line x1="780" y1="180" x2="940" y2="120" stroke="#b07a1e" stroke-width="2" class="flow"></line>
          <line x1="1080" y1="120" x2="1200" y2="120" stroke="#b07a1e" stroke-width="2" class="flow"></line>

          <rect x="10" y="80" width="140" height="80" stroke="#131211" stroke-width="1.5" fill="#f3efe6"></rect>
          <text class="node-name" x="80" y="115" text-anchor="middle" font-size="26" fill="#131211">Source</text>
          <text class="node-note" x="80" y="140" text-anchor="middle" font-size="11" fill="#5a554c">the cited page</text>

          <rect x="330" y="80" width="140" height="80" stroke="#131211" stroke-width="1.5" fill="#f3efe6"></rect>
          <text class="node-name" x="400" y="115" text-anchor="middle" font-size="26" fill="#131211">Snapshot</text>
          <text class="node-note" x="400" y="140" text-anchor="middle" font-size="11" fill="#5a554c">hashed, frozen</text>

          <rect x="640" y="30" width="140" height="60" stroke="#131211" stroke-width="1.5" fill="#f3efe6"></rect>
          <text class="node-name" x="710" y="66" text-anchor="middle" font-size="22" fill="#131211">Operator A</text>
          <rect x="640" y="90" width="140" height="60" stroke="#131211" stroke-width="1.5" fill="#f3efe6"></rect>
          <text class="node-name" x="710" y="126" text-anchor="middle" font-size="22" fill="#131211">Operator B</text>
          <rect x="640" y="150" width="140" height="60" stroke="#131211" stroke-width="1.5" fill="#f3efe6"></rect>
          <text class="node-name" x="710" y="186" text-anchor="middle" font-size="22" fill="#131211">Operator C</text>
          <text class="node-note" x="710" y="240" text-anchor="middle" font-size="11" fill="#5a554c">three independent · they fetch, test, and sign</text>

          <rect x="940" y="80" width="140" height="80" stroke="#131211" stroke-width="1.5" fill="#131211"></rect>
          <text class="node-name" x="1010" y="115" text-anchor="middle" font-size="26" fill="#f3efe6">Seal</text>
          <text class="node-note" x="1010" y="140" text-anchor="middle" font-size="11" fill="#c9c3b7">every 5 minutes</text>
          <circle cx="1010" cy="200" r="6" fill="#b07a1e" class="pulse"></circle>
          <circle cx="1040" cy="200" r="6" fill="#b07a1e" class="pulse"></circle>
          <circle cx="980" cy="200" r="6" fill="#b07a1e" class="pulse"></circle>
          <text class="node-note" x="1010" y="240" text-anchor="middle" font-size="11" fill="#5a554c">countersigned by independent witnesses</text>

          <rect x="1200" y="80" width="100" height="80" stroke="#b07a1e" stroke-width="2" fill="#f3efe6"></rect>
          <text class="node-name" x="1250" y="115" text-anchor="middle" font-size="26" fill="#131211">Learner</text>
          <text class="node-note" x="1250" y="140" text-anchor="middle" font-size="11" fill="#5a554c">syncs last</text>
        </svg>`;

/** The three cards under the diagram: the use case, the provenance, the truth. */
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

/** The five values, as a ledger panel. The paper's goals list, in its words. */
const VALUES: readonly { readonly head: string; readonly gloss: string }[] = [
  {
    head: "Owned by no lab.",
    gloss: "No model provider funds, runs, or validates the record.",
  },
  {
    head: "Facts, never opinions.",
    gloss:
      "What a cited source said or what a reproducible transcript shows. No rankings, no scores.",
  },
  {
    head: "Rewards for being right, never for being busy.",
    gloss:
      "Contributors are paid when the facts they backed are read and survive. Errors are clawed back and attributed, forever.",
  },
  {
    head: "Checkable by anyone, offline.",
    gloss: "Trust is not required; the proof travels with the record.",
  },
  {
    head: "Exit is the only real check.",
    gloss:
      "The code is open, the data is public domain, and the whole log is forkable.",
  },
];

export function renderLanding(ctx: PageContext): string {
  void ctx;
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
        <p class="eyebrow eyebrow-accent">
          THE SEALED FEED FOR MODELS THAT KEEP LEARNING
        </p>
        <h1 class="display hero-title">Proof first. <em>Use second.</em></h1>
        <p class="hero-sub">
          A public log of small cited facts about the AI ecosystem, built to be
          learned from. Every fact a model takes in arrives with its provenance
          proven, and with proof of truth wherever a test can reach.
        </p>
      </section>

      <section class="diagram row">
        <div class="panel diagram-panel">
          ${PIPELINE}
          <div class="pipeline-legend mono">
            <span>CAPTURED → HASHED → CHECKED ×3 → SEALED → WITNESSED → DATED → LEARNED</span>
            <span>A LEARNER SYNCS FROM ITS LAST SEALED POSITION</span>
          </div>
        </div>
      </section>

      <section class="cards row">
        ${CARDS.map(
          (card) => html`<article class="card">
          <p class="eyebrow eyebrow-label eyebrow-accent">${card.label}</p>
          <h2 class="display card-head">${card.head}</h2>
          <p class="card-body">${card.body}</p>
        </article>`,
        )}
      </section>

      <section class="duo">
        <div class="duo-col row">
          <p class="eyebrow eyebrow-accent">BUILT FOR MODELS THAT TRAIN FROM IT</p>
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
          <p class="eyebrow eyebrow-accent">PROVENANCE OF WHAT A MODEL LEARNED</p>
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

      <section class="tiers row">
        <div class="tiers-copy">
          <p class="eyebrow eyebrow-accent">TWO TIERS OF EVIDENCE</p>
          <h2 class="display tiers-title">
            Provenance is the floor.
            <em>Truth, wherever a test can reach.</em>
          </h2>
          <p class="tiers-body">
            Verified means three independent operators confirmed that the source
            says what the entry says. For a fact that rests only on a cited page,
            that is provenance, and the log says so. Where a claim can be
            measured, a metered call, a probe to a limit, a reproduced prompt, the
            submitter freezes the test and validators run it themselves under a
            published rule, each recording its own receipt. The entry moves past
            "a source said it" toward "this was observed to hold", and its tier
            tells a learner which it is holding.
          </p>
        </div>
        <div class="panel values">
          <div class="values-head">
            <p class="eyebrow eyebrow-label eyebrow-muted">WHAT WE HOLD TO</p>
          </div>
          ${VALUES.map(
            (value) => html`<div class="value">
            <p class="display value-head">${value.head}</p>
            <p class="value-gloss">${value.gloss}</p>
          </div>`,
          )}
        </div>
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
 * Warm paper ground, near-black type and rules, one amber accent for the feed.
 * Instrument Serif for display, Manrope for body, JetBrains Mono for the
 * eyebrows and the labels, each with a real fallback stack, because a page whose
 * meaning depends on a font that failed to load is a page that failed.
 *
 * The artboard is drawn at one width (1440 px); everything below that is fluid.
 * The content column stops at 1440 px, the side padding is 48 px and 24 px on a
 * phone, the display sizes step down with clamp() so no headline breaks a word,
 * and the three-up and two-up grids stack under 900 px.
 */
export const LANDING_CSS = `
/* ---------------------------------------------------------------------------
   The apex landing page (D-062, direction C). Its own namespace: body.landing.
   --------------------------------------------------------------------------- */

.landing {
  --ground: #f3efe6;
  --panel: #faf8f4;
  --ink: #131211;
  --muted: #3d3a34;
  --muted-2: #5a554c;
  --rule: #d9d2c4;
  --amber: #b07a1e;
  --display: "Instrument Serif", Georgia, "Times New Roman", serif;
  --body: "Manrope", "Helvetica Neue", Arial, sans-serif;
  --mono: "JetBrains Mono", Menlo, Consolas, monospace;
  --pad: 48px;
  margin: 0;
  background: var(--ground);
  color: var(--ink);
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
  color: var(--amber);
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

.eyebrow-accent {
  color: var(--amber);
}

.eyebrow-muted {
  color: var(--muted-2);
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

.panel {
  border: 1px solid var(--ink);
  background: var(--panel);
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
  border-bottom: 1px solid var(--ink);
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
}

.topcta {
  display: flex;
  gap: 10px;
}

/* Scoped under .landing so these out-specify the "a { color: inherit }" rule
   above: a filled button that inherited the body colour is a black block with an
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
  letter-spacing: 0.01em;
  white-space: nowrap;
}

.landing .btn-primary {
  background: var(--ink);
  color: var(--ground);
  font-weight: 600;
  transition: background 0.25s ease;
}

.landing .btn-primary:hover {
  background: var(--amber);
  color: var(--ground);
}

.landing .btn-ghost {
  border: 1px solid var(--ink);
  color: var(--ink);
  font-weight: 500;
  transition: border-color 0.25s ease, color 0.25s ease;
}

.landing .btn-ghost:hover {
  border-color: var(--amber);
  color: var(--amber);
}

/* --- the hero ------------------------------------------------------------- */

.hero {
  display: flex;
  flex-direction: column;
  gap: 22px;
  padding-top: 72px;
  padding-bottom: 40px;
}

/* clamp() rather than one size: at 1440 the artboard's 148px, and small enough
   on a phone that not one word of it has to break. */
.hero-title {
  max-width: 1200px;
  font-size: clamp(46px, 10.2vw, 148px);
  line-height: 0.9;
  letter-spacing: -0.03em;
}

.hero-title em {
  font-style: italic;
}

.hero-sub {
  margin: 0;
  max-width: 820px;
  font-size: clamp(18px, 1.6vw, 22px);
  line-height: 1.5;
  color: var(--muted);
  text-wrap: pretty;
}

/* --- the diagram panel ---------------------------------------------------- */

.diagram-panel {
  display: flex;
  flex-direction: column;
  gap: 18px;
  padding: 40px 32px 28px 32px;
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
  gap: 10px 24px;
  font-size: 11px;
  letter-spacing: 0.2em;
  line-height: 1.6;
  color: var(--muted-2);
  border-top: 1px solid var(--rule);
  padding-top: 14px;
}

/* --- the three cards ------------------------------------------------------ */

.cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 24px;
  padding-top: 40px;
  padding-bottom: 64px;
}

.card {
  display: flex;
  flex-direction: column;
  gap: 8px;
  border-top: 2px solid var(--ink);
  padding-top: 14px;
}

.card-head {
  font-size: clamp(24px, 2.2vw, 30px);
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
  border-top: 1px solid var(--ink);
  border-bottom: 1px solid var(--ink);
}

.duo-col {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding-top: 64px;
  padding-bottom: 64px;
}

.duo-col:first-child {
  border-right: 1px solid var(--ink);
}

.duo-title {
  font-size: clamp(30px, 3.2vw, 44px);
  line-height: 1.08;
}

.duo-body {
  margin: 0;
  font-size: clamp(16px, 1.3vw, 17px);
  line-height: 1.6;
  color: var(--muted);
  text-wrap: pretty;
}

/* --- the two tiers, and the values ledger --------------------------------- */

.tiers {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 48px;
  align-items: start;
  padding-top: 72px;
  padding-bottom: 72px;
}

.tiers-copy {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.tiers-title {
  font-size: clamp(38px, 5vw, 72px);
  line-height: 0.96;
  letter-spacing: -0.02em;
}

.tiers-title em {
  font-style: italic;
}

.tiers-body {
  margin: 0;
  font-size: clamp(16px, 1.3vw, 17px);
  line-height: 1.6;
  color: var(--muted);
  text-wrap: pretty;
}

.values {
  display: flex;
  flex-direction: column;
}

.values-head {
  padding: 22px 24px;
  border-bottom: 1px solid var(--ink);
}

.value {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 18px 24px;
  border-bottom: 1px solid var(--rule);
}

.value:last-child {
  border-bottom: 0;
}

.value-head {
  font-size: 26px;
  line-height: 1.15;
}

.value-gloss {
  margin: 0;
  font-size: 13px;
  line-height: 1.5;
  color: var(--muted-2);
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
  border-top: 1px solid var(--ink);
  font-size: 11px;
  letter-spacing: 0.2em;
  line-height: 1.6;
  color: var(--muted-2);
}

/* --- motion --------------------------------------------------------------
   The whole of it, and there is no script: the feed lines are dashed strokes
   whose offset moves, and the witness dots breathe. Both stop under
   prefers-reduced-motion, and the diagram still reads exactly the same.
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

/* --- under 900 px: the grids stack --------------------------------------- */

@media (max-width: 900px) {
  .cards,
  .duo,
  .tiers {
    grid-template-columns: minmax(0, 1fr);
  }
  .tiers {
    gap: 40px;
  }
  .duo-col:first-child {
    border-right: 0;
    border-bottom: 1px solid var(--ink);
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
}

/* --- under 700 px: less side air, tighter labels -------------------------- */

@media (max-width: 700px) {
  .landing {
    --pad: 24px;
  }
  .hero {
    padding-top: 48px;
    padding-bottom: 32px;
  }
  .cards {
    padding-top: 32px;
    padding-bottom: 48px;
  }
  .tiers {
    padding-top: 48px;
    padding-bottom: 48px;
  }
  .pipeline-legend,
  .landing-footer {
    font-size: 10px;
    letter-spacing: 0.12em;
  }
  .value {
    padding: 16px 18px;
  }
  .values-head {
    padding: 18px 18px;
  }
  .value-head {
    font-size: 24px;
  }
}
`;

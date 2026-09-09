/**
 * The apex landing page (decision D-021): what nomankind is, for someone who
 * arrived at nomankind.ai and has never heard of it.
 *
 * The one page that is NOT in the shared layout. It has no header nav and no
 * environment badge, because it is not an instrument panel — it is the front
 * door, and the app lives at app.nomankind.ai. So this returns a whole document
 * of its own, built the same CSP-safe way: no inline style attribute, no script,
 * one stylesheet from this Worker and one from Google Fonts.
 *
 * Its own voice and its own visual system (D-021, D-023): warm white ground,
 * near-black type, one amber accent, a serif display face over a sans body. It
 * shares no class name with the app stylesheet, which is why LANDING_CSS below
 * is served separately at /static/landing.css rather than appended to app.css.
 *
 * Every motion the prototype expressed with script is expressed here with
 * keyframes instead, because the CSP forbids a script and there is none: the
 * hero rises on a load-time animation, the sections below reveal on a
 * scroll-driven timeline only where the browser supports one and sit still
 * otherwise, and the seal ring is inline SVG turned by a CSS rotation. All of it
 * stops under prefers-reduced-motion.
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

/** The turning seal ring behind the hero. Amber at low opacity, decorative. */
const SEAL_RING = html`<svg
        class="seal"
        viewBox="0 0 920 920"
        fill="none"
        aria-hidden="true"
      >
        <g class="ring">
          <circle cx="460" cy="460" r="440" stroke="rgba(19,18,17,0.10)" stroke-width="1"></circle>
          <circle cx="460" cy="460" r="440" stroke="rgba(176,122,30,0.35)" stroke-width="1" stroke-dasharray="2 22"></circle>
          <circle cx="460" cy="460" r="330" stroke="rgba(19,18,17,0.08)" stroke-width="1" stroke-dasharray="120 40 8 40"></circle>
        </g>
        <g class="ring2">
          <circle cx="460" cy="460" r="380" stroke="rgba(19,18,17,0.07)" stroke-width="1" stroke-dasharray="1 9"></circle>
          <circle cx="460" cy="460" r="250" stroke="rgba(176,122,30,0.22)" stroke-width="1" stroke-dasharray="60 300"></circle>
        </g>
        <circle cx="460" cy="460" r="3" fill="#b07a1e"></circle>
      </svg>`;

/** The five values, as a vertical ledger. The paper's goals list, in its words. */
const VALUES: readonly { readonly head: string; readonly gloss: string }[] = [
  {
    head: "Owned by no lab.",
    gloss:
      "No model provider funds, runs, or validates the record. The maintainer runs the pipes and never the judgment.",
  },
  {
    head: "Facts, never opinions.",
    gloss:
      "An entry states what a cited source said or what a reproducible transcript shows. No rankings, no scores, no characterizations.",
  },
  {
    head: "Rewards for being right, never for being busy.",
    gloss:
      "Contributors are paid when the facts they backed are read and survive. Errors are clawed back and attributed, forever.",
  },
  {
    head: "Checkable by anyone, offline.",
    gloss:
      "Every entry is hashed, signed, and sealed into a witnessed log. Trust is not required; the proof travels with the record.",
  },
  {
    head: "Exit is the only real check.",
    gloss:
      "The code is open, the data is public domain, and the whole log is forkable. If nomankind breaks its own rules, anyone leaves with the entire record.",
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
      content="A public record of what changed in the AI ecosystem, where every fact carries its proof before any model learns it."
    />
    <link
      rel="stylesheet"
      href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&amp;family=JetBrains+Mono:wght@400&amp;family=Manrope:wght@400;500;600&amp;display=swap"
    />
    <link rel="stylesheet" href="/static/landing.css" />
  </head>
  <body class="landing">
    <header class="topbar hero-in d1">
      <span class="wordmark eyebrow">NOMANKIND</span>
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

    <main class="page">
      <div class="glow" aria-hidden="true"></div>
      ${SEAL_RING}

      <section class="hero">
        <h1 class="display hero-title hero-in d2">Proof first. Use second.</h1>
        <p class="hero-sub hero-in d3">
          A public record of what changed in the AI ecosystem, where every fact
          carries its proof before any model learns it.
        </p>
        <div class="scrollcue hero-in d4">
          <span class="eyebrow eyebrow-faint">SCROLL</span>
          <span class="scrolltrack"><span class="scrollhint"></span></span>
        </div>
      </section>

      <section class="band reveal">
        <p class="eyebrow eyebrow-accent">WHAT IT IS</p>
        <h2 class="display band-title">
          Models learn from the world. Nobody writes down where each fact came
          from until the weights already hold it.
        </h2>
        <p class="band-body">
          nomankind turns the order around. Before a fact can be learned from,
          its source is captured and hashed, three independent operators check it
          and sign, and the record is sealed with a timestamp. Only then is it
          offered to a model. Prices, rate limits, deprecations, model behavior:
          an append-only log of small cited facts, owned by no lab.
        </p>
      </section>

      <section class="band reveal">
        <p class="eyebrow eyebrow-accent">WHY IT MATTERS</p>
        <h2 class="display band-title">
          Sources rot. Labs edit their own pages quietly. A frozen model cannot
          see any of it, and a model that keeps learning has nowhere neutral to
          look.
        </h2>
        <p class="band-body">
          Even if the original page is later edited or destroyed, the sealed,
          dated, independently verified record of what it said still stands, and
          anyone can check it offline with two files and one script.
        </p>
      </section>

      <section class="ledger">
        <p class="eyebrow eyebrow-accent reveal">WHAT WE HOLD TO</p>
        ${VALUES.map(
          (value) => html`<div class="value reveal">
          <p class="display value-head">${value.head}</p>
          <p class="value-gloss">${value.gloss}</p>
        </div>`,
        )}
      </section>

      <section class="band reveal">
        <p class="eyebrow eyebrow-accent">TWO TIERS OF EVIDENCE</p>
        <h2 class="display closing-title">
          Provenance is the floor.<br /><em>Truth, wherever a test can reach.</em>
        </h2>
        <p class="band-body">
          Every entry rests on a cited source that three independent operators
          confirmed says what the entry says. Where a claim can be measured
          cheaply, a metered call, a probe, a reproduced prompt, validators run
          the test themselves and record their own receipts. The entry says which
          kind it is, so a reader always knows what they are holding.
        </p>
      </section>
    </main>

    <footer class="landing-footer">
      <span class="eyebrow eyebrow-faint">CODE APACHE-2.0 · DATA CC0</span>
    </footer>
  </body>
</html>
`.markup;
}

/**
 * The landing page's whole stylesheet, served at /static/landing.css.
 *
 * Separate from APP_CSS on purpose: the landing is its own visual system
 * (D-021, D-023) and shares not one class with the instrument panel, so the two
 * sheets can move independently and neither builder edits the other's rules.
 *
 * Warm white ground, near-black type, one amber accent. Instrument Serif for
 * display, Manrope for body, JetBrains Mono for the eyebrows, each with a real
 * fallback stack, because a page whose meaning depends on a font that failed to
 * load is a page that failed.
 */
export const LANDING_CSS = `
/* ---------------------------------------------------------------------------
   The apex landing page (D-021). Its own namespace: body.landing.
   --------------------------------------------------------------------------- */

.landing {
  --ground: #faf8f4;
  --ink: #131211;
  --amber: #b07a1e;
  --ink-70: rgba(19, 18, 17, 0.7);
  --ink-60: rgba(19, 18, 17, 0.6);
  --ink-35: rgba(19, 18, 17, 0.35);
  --ink-28: rgba(19, 18, 17, 0.28);
  --ink-12: rgba(19, 18, 17, 0.12);
  --ink-10: rgba(19, 18, 17, 0.1);
  --display: "Instrument Serif", Georgia, "Times New Roman", serif;
  --body: "Manrope", "Helvetica Neue", Arial, sans-serif;
  --eyebrow: "JetBrains Mono", Menlo, Consolas, monospace;
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

.eyebrow {
  font-family: var(--eyebrow);
  font-weight: 400;
  font-size: 11px;
  letter-spacing: 0.3em;
  margin: 0;
}

.eyebrow-accent {
  color: var(--amber);
}

.eyebrow-faint {
  font-size: 10px;
  color: var(--ink-35);
}

/* --- the top bar ---------------------------------------------------------- */

.topbar {
  position: relative;
  z-index: 2;
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  align-items: center;
  gap: 24px;
  padding: 22px 48px;
  box-sizing: border-box;
}

.wordmark {
  font-size: 12px;
  letter-spacing: 0.32em;
  color: var(--amber);
}

.topnav {
  display: flex;
  gap: 32px;
  font-size: 14px;
  color: var(--ink-70);
}

.topcta {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}

/* Scoped under .landing so these out-specify the "a { color: inherit }" rule
   above: a filled button that inherited the body colour is a black pill with an
   invisible label. */
.landing .btn-primary,
.landing .btn-ghost {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: 44px;
  padding: 0 22px;
  font-size: 14px;
  font-weight: 500;
  letter-spacing: 0.02em;
  border-radius: 999px;
  white-space: nowrap;
}

.landing .btn-primary {
  background: var(--ink);
  color: var(--ground);
  transition: transform 0.25s ease, background 0.25s ease;
}

.landing .btn-primary:hover {
  background: var(--amber);
  color: var(--ground);
  transform: translateY(-2px);
}

.landing .btn-ghost {
  border: 1px solid var(--ink-28);
  color: var(--ink);
  transition: border-color 0.25s ease, color 0.25s ease, transform 0.25s ease;
}

.landing .btn-ghost:hover {
  border-color: var(--amber);
  color: var(--amber);
  transform: translateY(-2px);
}

/* --- the page: one centred column, generous air --------------------------- */

.page {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  padding: 0 24px;
}

.glow {
  position: absolute;
  top: -340px;
  left: 50%;
  width: 1400px;
  max-width: 200vw;
  height: 1100px;
  margin-left: -700px;
  pointer-events: none;
  background: radial-gradient(
    ellipse at center,
    rgba(217, 164, 65, 0.22) 0%,
    rgba(217, 164, 65, 0.07) 32%,
    rgba(250, 248, 244, 0) 62%
  );
}

/* --- the seal ring -------------------------------------------------------- */

.seal {
  position: absolute;
  top: 100px;
  left: 50%;
  width: 920px;
  height: 920px;
  max-width: 170vw;
  max-height: 170vw;
  margin-left: -460px;
  opacity: 0.55;
  pointer-events: none;
}

.ring,
.ring2 {
  transform-origin: 460px 460px;
}

.ring {
  animation: spin 160s linear infinite;
}

.ring2 {
  animation: spinback 240s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

@keyframes spinback {
  from { transform: rotate(0deg); }
  to { transform: rotate(-360deg); }
}

/* --- the hero ------------------------------------------------------------- */

.hero {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 28px;
  max-width: 860px;
  padding: 200px 0 0 0;
}

/* Two lines by measure rather than by a <br>: the break belongs to the type,
   and a balanced wrap in a narrow measure puts it at the sentence boundary. */
.hero-title {
  max-width: 640px;
  font-size: clamp(52px, 9vw, 104px);
  line-height: 0.98;
  letter-spacing: -0.02em;
  text-wrap: balance;
}

.hero-sub {
  margin: 0;
  max-width: 620px;
  font-size: 20px;
  line-height: 1.6;
  color: var(--ink-70);
  text-wrap: pretty;
}

.scrollcue {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  margin-top: 48px;
}

.scrolltrack {
  display: block;
  width: 1px;
  height: 64px;
  background: var(--ink-12);
  overflow: hidden;
}

.scrollhint {
  display: block;
  width: 1px;
  height: 64px;
  background: var(--amber);
  animation: drop 2.4s ease-in-out infinite;
}

@keyframes drop {
  0% { transform: scaleY(0); transform-origin: top; }
  60% { transform: scaleY(1); transform-origin: top; }
  61% { transform-origin: bottom; }
  100% { transform: scaleY(0); transform-origin: bottom; }
}

/* --- the reading bands ---------------------------------------------------- */

.band {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 26px;
  max-width: 720px;
  padding: 220px 0 0 0;
}

.band-title {
  font-size: clamp(30px, 4.4vw, 44px);
  line-height: 1.15;
  letter-spacing: -0.01em;
  text-wrap: balance;
}

.band-body {
  margin: 0;
  font-size: 18px;
  line-height: 1.7;
  color: var(--ink-70);
  text-wrap: pretty;
}

.closing-title {
  font-size: clamp(36px, 5.8vw, 58px);
  line-height: 1.05;
  letter-spacing: -0.015em;
  text-wrap: balance;
}

/* --- the five values, as a ledger ---------------------------------------- */

.ledger {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  width: 100%;
  max-width: 780px;
  padding: 240px 0 0 0;
}

.ledger .eyebrow {
  margin-bottom: 44px;
}

.value {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 44px 0;
  border-top: 1px solid var(--ink-10);
}

.value:last-child {
  border-bottom: 1px solid var(--ink-10);
}

.value-head {
  font-size: clamp(28px, 3.8vw, 40px);
  line-height: 1.1;
}

.value-gloss {
  margin: 0;
  max-width: 560px;
  font-size: 16px;
  line-height: 1.6;
  color: var(--ink-60);
}

/* --- the footer: the licence line and nothing else ----------------------- */

.landing-footer {
  display: flex;
  justify-content: center;
  padding: 200px 24px 48px 24px;
}

.landing-footer .eyebrow {
  font-size: 11px;
  letter-spacing: 0.12em;
  color: rgba(19, 18, 17, 0.3);
}

/* --- motion --------------------------------------------------------------
   The hero rises once, on load. The bands below reveal on a scroll-driven
   timeline only where the browser has one; everywhere else they are simply
   there, which is the correct fallback for prose.
   ------------------------------------------------------------------------- */

@keyframes rise {
  from { opacity: 0; transform: translateY(28px); }
  to { opacity: 1; transform: translateY(0); }
}

.hero-in {
  animation: rise 1.4s cubic-bezier(0.2, 0.7, 0.2, 1) both;
}

.d1 { animation-delay: 0.15s; }
.d2 { animation-delay: 0.45s; }
.d3 { animation-delay: 0.75s; }
.d4 { animation-delay: 1.05s; }

@supports (animation-timeline: view()) {
  .reveal {
    animation: rise 1s cubic-bezier(0.2, 0.7, 0.2, 1) both;
    animation-timeline: view();
    animation-range: entry 0% entry 45%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .landing *,
  .landing *::before,
  .landing *::after {
    animation: none !important;
    transition: none !important;
  }
  .hero-in,
  .reveal {
    opacity: 1;
    transform: none;
  }
  .scrolltrack {
    display: none;
  }
}

/* --- under 700 px --------------------------------------------------------- */

@media (max-width: 700px) {
  .topbar {
    grid-template-columns: 1fr;
    justify-items: center;
    gap: 18px;
    padding: 20px 20px;
    text-align: center;
  }
  .topnav {
    flex-wrap: wrap;
    justify-content: center;
    gap: 18px;
    font-size: 13px;
  }
  .topcta {
    justify-content: center;
  }
  .seal {
    top: 60px;
  }
  .hero {
    padding-top: 120px;
    gap: 22px;
  }
  .hero-sub {
    font-size: 17px;
  }
  .band {
    padding-top: 140px;
    gap: 20px;
  }
  .band-body {
    font-size: 16px;
  }
  .ledger {
    padding-top: 150px;
  }
  .value {
    padding: 32px 0;
  }
  .landing-footer {
    padding-top: 120px;
  }
}
`;

/**
 * The whole stylesheet, as classes.
 *
 * Decision D-018, direction C "Instrument": a dark instrument panel, dense mono
 * tables, three accents and no decoration. The approved prototype expresses that
 * with inline `style` attributes; this file expresses exactly the same look as
 * classes, because the content-security-policy in src/ui/html.ts forbids inline
 * styles outright — a page that can carry style attributes is a page that can
 * carry markup from a claim.
 *
 * Sizes and colours are not policy numbers, so they live here beside the rules
 * that use them rather than in src/policy.ts. Policy is what the record runs
 * on; a border width is what a border is.
 *
 * Served at /static/app.css through `cssResponse`.
 */

/**
 * The palette and the shell, the header, the tables, the badges and the panels:
 * everything every page shares.
 */
export const APP_CSS = `
/* --- palette (D-018 direction C) ------------------------------------- */
:root {
  --bg: #0f1216;
  --panel: #161a20;
  --border: #262c35;
  --border-soft: #1d2229;
  --hover: #1b2028;
  --text: #e6e9ee;
  --muted: #aab2bd;
  --dim: #7f8794;
  --accent: #7fd1c4;
  --accent-edge: #2c4a45;
  --warn: #e0b458;
  --danger: #d67a6a;
  --sans: "Space Grotesk", "Helvetica Neue", Arial, sans-serif;
  --mono: "JetBrains Mono", Menlo, "Courier New", monospace;
}

/* --- shell ------------------------------------------------------------ */
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.5;
  -webkit-text-size-adjust: 100%;
}
a { color: var(--text); text-decoration: none; }
a:hover { color: var(--accent); }
a:focus-visible, .chip:focus-visible, .btn:focus-visible {
  outline: 1px solid var(--accent);
  outline-offset: 2px;
}
.mono, code, pre { font-family: var(--mono); }
.muted { color: var(--muted); }
.dim { color: var(--dim); }
.accent { color: var(--accent); }
.warn { color: var(--warn); }
.danger { color: var(--danger); }
.break { word-break: break-all; }
.right { text-align: right; }
.nowrap { white-space: nowrap; }

/* --- header ----------------------------------------------------------- */
.header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 32px;
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 10;
  background: var(--bg);
  flex-wrap: wrap;
}
.wordmark {
  display: flex;
  align-items: center;
  gap: 10px;
  min-height: 44px;
}
.wordmark .mark { color: var(--accent); flex: none; }
.wordmark-text { font-weight: 600; font-size: 16px; }
.env {
  font-size: 11px;
  color: var(--accent);
  border: 1px solid var(--accent-edge);
  padding: 2px 6px;
  letter-spacing: 0.04em;
}
.nav-list {
  display: flex;
  gap: 24px;
  margin-left: auto;
  font-size: 13px;
  flex-wrap: wrap;
}
.nav {
  color: var(--muted);
  padding: 12px 2px;
  min-height: 44px;
  display: inline-flex;
  align-items: center;
  border-bottom: 2px solid transparent;
}
.nav:hover { color: var(--text); }
.nav-active { color: var(--text); border-bottom-color: var(--accent); }

/* --- main and footer -------------------------------------------------- */
.main {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 24px 32px 40px 32px;
  max-width: 1440px;
}
.footer {
  display: flex;
  gap: 16px;
  justify-content: space-between;
  flex-wrap: wrap;
  padding: 16px 32px 24px 32px;
  border-top: 1px solid var(--border);
  font-size: 12px;
  color: var(--dim);
}
.footer-links { display: flex; gap: 16px; }
.footer-links a { color: var(--muted); }

/* --- headings and prose ---------------------------------------------- */
.page-head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 16px;
  flex-wrap: wrap;
}
h1 { font-size: 22px; font-weight: 600; margin: 0; letter-spacing: -0.01em; }
h2 { font-size: 16px; font-weight: 500; margin: 0; }
h3 { font-size: 13px; font-weight: 500; margin: 0; }
.lede {
  font-size: 15px;
  line-height: 1.55;
  color: var(--muted);
  max-width: 820px;
  margin: 0;
}
.headline {
  font-size: 32px;
  font-weight: 600;
  line-height: 1.15;
  letter-spacing: -0.02em;
  max-width: 760px;
  margin: 0;
}
.claim-head {
  font-size: 26px;
  font-weight: 600;
  line-height: 1.25;
  letter-spacing: -0.01em;
  margin: 0;
}
.note { font-size: 12px; color: var(--dim); }
.crumbs {
  display: flex;
  gap: 8px;
  align-items: center;
  font-size: 12px;
  color: var(--dim);
}

/* --- panels ----------------------------------------------------------- */
.panel {
  background: var(--panel);
  border: 1px solid var(--border);
  display: flex;
  flex-direction: column;
}
.panel-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}
.panel-body { padding: 14px 16px; display: flex; flex-direction: column; gap: 10px; }
/* The documentation pages (policy, api, genesis) carry a panel's heading as one
   element rather than a .panel-head holding a label beside it, so .panel-title is
   the same header row: the same padding, the same rule under it. Their prose and
   their blocks are direct children of the panel too, which is why the padding a
   .panel-body would have given them is given here instead. */
.panel-title {
  margin: 0;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  font-size: 16px;
  font-weight: 500;
}
.panel > .note { padding: 0 16px; }
.panel > pre.block { margin: 0 16px 14px 16px; }
.panel-label {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--dim);
  letter-spacing: 0.06em;
}
.panel-empty { padding: 24px 16px; font-size: 13px; color: var(--dim); }

/* --- counters --------------------------------------------------------- */
.counters {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}
.counter {
  background: var(--panel);
  border: 1px solid var(--border);
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.counter-label { font-family: var(--mono); font-size: 11px; color: var(--dim); }
.counter-value { font-size: 28px; font-weight: 500; line-height: 1.1; }
.counter-note { font-family: var(--mono); font-size: 11px; color: var(--dim); }

/* --- dense tables ----------------------------------------------------- */
/* Two selectors, one rule set. The app pages write \`table.dense\` and the
   documentation pages write \`table.table\`; naming both on every rule is what
   keeps a column added on either side from drifting into a look of its own.

   \`min-width\` is a floor and not a width: with \`width: 100%\` alone a ten-column
   table squeezed into a phone's viewport collapses into a column of wrapped
   fragments, and a table nobody can read row-wise is not a record. The floor
   makes it keep its columns and scroll inside .table-wrap instead. */
.table-wrap { overflow-x: auto; }
table.dense,
table.table {
  width: 100%;
  min-width: 640px;
  border-collapse: collapse;
  font-family: var(--mono);
  font-size: 12px;
}
table.dense caption,
table.table caption {
  text-align: left;
  padding: 12px 16px;
  font-family: var(--sans);
  font-size: 13px;
  font-weight: 500;
  border-bottom: 1px solid var(--border);
}
table.dense th,
table.table th {
  text-align: left;
  font-weight: 400;
  font-size: 11px;
  color: var(--dim);
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
table.dense td,
table.table td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-soft);
  vertical-align: baseline;
}
table.dense tr.row:hover,
table.table tr.row:hover { background: var(--hover); }
table.dense td.prose,
table.table td.prose {
  font-family: var(--sans);
  font-size: 13px;
  color: var(--muted);
}
table.dense td.prose a,
table.table td.prose a { color: var(--text); }
/* An agent id and a hash are each one token. Broken per character across lines
   they can be neither read nor compared, so inside a table they never break: the
   row scrolls instead. Where a value is too long to show at all the page
   shortens it itself (shortHash in src/ui/html.ts), which is a decision the
   renderer makes and not one the browser makes mid-token. */
table.dense td.break,
table.table td.break {
  white-space: nowrap;
  word-break: normal;
}

/* --- badges ----------------------------------------------------------- */
.badge {
  display: inline-block;
  font-family: var(--mono);
  font-size: 11px;
  padding: 3px 8px;
  border: 1px solid var(--border);
  color: var(--muted);
  white-space: nowrap;
}
.s-verified { color: var(--accent); border-color: var(--accent-edge); }
.s-draft { color: var(--warn); border-color: var(--warn); }
.s-superseded { color: var(--muted); border-color: var(--border); }
.s-rejected { color: var(--danger); border-color: var(--danger); }
.s-overturned { color: var(--danger); border-color: var(--danger); }
.s-other { color: var(--dim); border-color: var(--border); }
.b-stale { color: var(--warn); border-color: var(--warn); }
.b-fresh { color: var(--accent); border-color: var(--accent-edge); }
.b-open { color: var(--warn); border-color: var(--warn); }
.b-upheld { color: var(--danger); border-color: var(--danger); }
.b-failed { color: var(--dim); border-color: var(--border); }
/* An attestation's four states, in three readings: running, finished, out of
   time. An expired attestation is not a low score and must not read as one. */
.b-answered { color: var(--muted); border-color: var(--border); }
.b-scored { color: var(--accent); border-color: var(--accent-edge); }
.b-expired { color: var(--dim); border-color: var(--border); }

/* --- filter chips (a real form: no script anywhere) ------------------- */
.filters {
  background: var(--panel);
  border: 1px solid var(--border);
  padding: 12px 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.filter-row {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}
.filter-name {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--dim);
  min-width: 76px;
}
.chip {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 44px;
  padding: 4px 12px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--muted);
  border: 1px solid var(--border);
  background: transparent;
  cursor: pointer;
}
.chip:hover { border-color: var(--accent); color: var(--accent); }
.chip-on { color: var(--accent); border-color: var(--accent); }
/* The radio inside a chip label. Hidden, never removed: the chip IS the radio,
   so it stays focusable and stays keyboard-operable, and the label's own 44 px
   box is the hit target. display:none would take it out of the form. */
.chip input {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: 0;
  padding: 0;
  opacity: 0;
  pointer-events: none;
}
.chip:focus-within { border-color: var(--accent); color: var(--accent); }
.badges { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 44px;
  padding: 9px 14px;
  font-family: var(--sans);
  font-size: 13px;
  color: var(--muted);
  border: 1px solid var(--border);
  background: transparent;
  cursor: pointer;
}
.btn:hover { border-color: var(--accent); color: var(--accent); }
.btn-accent { color: var(--accent); border-color: var(--accent); }
.actions { display: flex; gap: 10px; flex-wrap: wrap; }

/* --- key/value blocks ------------------------------------------------- */
/* Two of them: dl.kv is the entry page's field list, where the term is a schema
   field name and the value is a stored value; dl.dl is the same block on the
   documentation pages, where the term is a header or a step and the value is a
   sentence. Same geometry, so both read as one thing; the documentation one gets
   a wider term column and prose values, because that is what it holds. */
dl.kv,
dl.dl {
  display: grid;
  grid-template-columns: 150px minmax(0, 1fr);
  gap: 8px 12px;
  margin: 0;
  font-size: 13px;
}
dl.kv dt,
dl.dl dt { color: var(--dim); }
dl.kv dd,
dl.dl dd {
  margin: 0;
  font-family: var(--mono);
  font-size: 12px;
  min-width: 0;
  overflow-wrap: anywhere;
}
dl.kv dd.prose { font-family: var(--sans); font-size: 13px; }
dl.dl {
  grid-template-columns: 220px minmax(0, 1fr);
  padding: 0 16px 14px 16px;
}
dl.dl dd { font-family: var(--sans); font-size: 13px; color: var(--muted); }
.grid-4 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px 14px;
}
.field { display: flex; flex-direction: column; gap: 2px; }
.field-name { font-family: var(--mono); font-size: 11px; color: var(--dim); }
.field-value { font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }

/* --- copyable blocks -------------------------------------------------- */
pre.block {
  margin: 0;
  padding: 10px 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  font-size: 11px;
  line-height: 1.6;
  color: var(--accent);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  overflow-x: auto;
}
pre.block.plain { color: var(--muted); }

/* --- the how-it-works strip (D-076) ----------------------------------- */
/* Eight steps across the top of the how-it-works page, each an anchor to the
   panel below it. A grid of eight and not a flex row: the eight are one strip
   and have to stay one strip, so they share the width rather than each taking
   the width of its own words. */
.steps {
  display: grid;
  grid-template-columns: repeat(8, minmax(0, 1fr));
  gap: 8px;
}
.step {
  border: 1px solid var(--border);
  background: var(--panel);
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-height: 64px;
}
.step-n { font-family: var(--mono); font-size: 11px; color: var(--dim); }
.step-t { font-size: 13px; color: var(--text); }
/* The step is itself the anchor, so the selector is a.step and not .step a:
   the strip's links take the page's text colour rather than the link colour. */
a.step { color: var(--text); }
/* The step's number where it repeats in the panel heading below, so a reader
   who followed an anchor lands on the number they clicked. */
.stage-num {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--accent);
  letter-spacing: 0.06em;
  margin-right: 10px;
}

/* --- prose paragraphs -------------------------------------------------- */
/* The documentation paragraph, as the artboards define it. Scoped to the
   elements that carry it as a paragraph — a <p>, and the sentence inside an
   .alert — because \`prose\` is already a table cell and a definition value
   elsewhere in this sheet, where it means "sans, not mono" and nothing else.
   An unscoped rule here would put a max-width and a border under those too. */
p.prose,
.alert .prose {
  font-size: 13px;
  line-height: 1.55;
  color: var(--muted);
  max-width: 820px;
  margin: 0;
}
p.prose a { color: var(--text); border-bottom: 1px solid var(--accent-edge); }

/* --- a rendered document ----------------------------------------------- */
/* The markdown renderer emits a document's lists, quotes, rules and deepest
   headings as the plain elements they are, and a plain element takes the
   browser's defaults: 14px near-white text, a 40px indent, 1em margins and no
   width cap — brighter and wider than the p.prose it sits between, which made a
   paragraph and the list under it read as two different documents. Scoped to
   .document, the class the document page puts on the panel body, so nothing
   else in this UI is touched. */
.document ul,
.document ol {
  font-size: 13px;
  line-height: 1.55;
  color: var(--muted);
  max-width: 820px;
  margin: 0;
  padding-left: 20px;
}
.document li + li { margin-top: 6px; }
.document blockquote {
  border-left: 1px solid var(--border);
  margin: 0;
  padding-left: 16px;
}
.document blockquote p { font-size: 13px; color: var(--muted); }
.document hr {
  border: 0;
  border-top: 1px solid var(--border);
  margin: 0;
}
.document h4 { font-size: 13px; font-weight: 500; }

/* --- the degraded band ------------------------------------------------- */
/* Drawn only when a stage is failing or needs attention, above the counters:
   the one place in this UI that says something is wrong, so it is bordered in
   the danger colour and says which stages and how many. */
.alert {
  border: 1px solid var(--danger);
  background: var(--panel);
  padding: 12px 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.alert-title { font-size: 13px; color: var(--danger); font-family: var(--mono); }

/* --- two columns, collapsing ------------------------------------------ */
.cols {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 12px;
}
.cols-side {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 360px;
  gap: 12px;
}
.stack { display: flex; flex-direction: column; gap: 12px; }
.stack-tight { display: flex; flex-direction: column; gap: 8px; }
.pager { display: flex; gap: 10px; justify-content: flex-end; }

@media (max-width: 900px) {
  .cols, .cols-side { grid-template-columns: minmax(0, 1fr); }
  /* Eight across is eight columns of one word each below the breakpoint. The
     strip wraps into as many rows as it needs instead. */
  .steps { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }
  .header, .main, .footer { padding-left: 16px; padding-right: 16px; }
  dl.kv, dl.dl { grid-template-columns: minmax(0, 1fr); gap: 2px 0; }
  dl.kv dt, dl.dl dt { margin-top: 8px; }
  /* On a phone the floor costs more than it buys. A documentation table is a
     term and a sentence about it, and 640px of table inside a 375px viewport
     pushed the sentence into a column three words wide and put the rest of it
     behind a sideways scroll. Below the breakpoint these lay out at the width
     they are given. */
  table.table { min-width: 0; }
  /* And the long values wrap. Above the breakpoint an id and a hash are each one
     token that never breaks, because a token broken per character can be neither
     read nor compared and the row scrolls instead; on a phone there is not
     enough width for that to be true of both the value and the prose beside it,
     so the value breaks where it must. overflow-wrap rather than break-all, so a
     value with a real break opportunity in it takes that one first, and only the
     cells that hold a long value: a column header still never breaks mid-word. */
  table.dense td.break,
  table.table td.break,
  table.dense td.mono,
  table.table td.mono {
    white-space: normal;
    word-break: normal;
    overflow-wrap: anywhere;
  }
}
`;

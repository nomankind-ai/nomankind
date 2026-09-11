/**
 * The home page: the counters, and the latest sealed entries.
 *
 * Four numbers and a table, and then the three ways to actually read the log —
 * the frozen reader, the delta stream, and the offline verify. The commands are
 * the ones that exist today (M17, M18 and the export/verify pair), spelled out
 * against this request's own origin, because a page that showed a route the
 * Worker does not serve would be the first thing a reader tried and the first
 * thing that failed.
 *
 * Decision D-100, the release window: a latest row whose content this reader has
 * not been served shows "released <date>" where the claim would be, exactly as
 * the entries listing does. The counters are untouched — they count entries, and
 * the window holds back content and never a count.
 *
 * Pure: every value comes off `HomeData`, which the route gathered. Nothing here
 * counts anything, and the one number named is TRUSTED_POOL_SWITCH, read from
 * src/policy.ts rather than typed out.
 */

import { TRUSTED_POOL_SWITCH } from "../../policy.js";
// The claim cell is the entries listing's own (decision D-100): the two tables
// show the same rows, and a release line written twice would be two lines to
// keep in step.
import { claimCell } from "./entries.js";
import {
  badge,
  fmtDate,
  fmtInstant,
  html,
  layout,
  raw,
  statusClass,
  type Safe,
} from "../html.js";
import type { EntryRow, HomeCounters, HomeData, PageContext } from "../types.js";

/**
 * Which domain the numbers above and the rows below were counted in
 * (decision D-071).
 *
 * The line is not decoration: a four that counted one domain and a four that
 * counted the log look exactly the same, so a page that filtered silently would
 * be a page whose counters cannot be checked. The seal head and the seal count
 * are the whole log's either way — a seal covers events, not a domain — and the
 * line says that too rather than leaving a reader to work it out.
 */
function domainLine(domain: string | null): Safe {
  if (domain === null) {
    return html`<p class="note">
      Counting all domains. Narrow with
      <span class="mono">?domain=&lt;slug&gt;</span>, which filters the verified,
      stale and trusted-pool counters and the entries below.
    </p>`;
  }
  return html`<p class="note">
    Counting the <span class="mono">${domain}</span> domain only: the verified,
    stale and trusted-pool counters and the entries below are this domain's.
    The head and the seal count are the whole log's, because a seal covers
    events and not a domain. <a href="/">All domains</a>.
  </p>`;
}

/** One counter tile: the label, the number, and the line under it. */
function counter(label: string, value: string, note: Safe): Safe {
  return html`<div class="counter">
    <div class="counter-label">${label}</div>
    <div class="counter-value">${value}</div>
    ${note}
  </div>`;
}

/** The four counters, in the prototype's order. */
function counters(c: HomeCounters): Safe {
  const head =
    c.sealedHead === null
      ? html`<div class="counter-note">no seal yet</div>`
      : html`<div class="counter-note">
          sealed ${fmtInstant(c.sealedAt)} · ${c.witnesses ?? 0} witnesses
        </div>`;
  return html`<div class="counters">
    ${counter(
      "VERIFIED",
      String(c.verified),
      html`<div class="counter-note accent">${c.seals} seals</div>`,
    )}
    ${counter(
      "STALE",
      String(c.stale),
      c.stale > 0
        ? html`<div class="counter-note warn">bounty accruing</div>`
        : html`<div class="counter-note">none stale</div>`,
    )}
    ${counter(
      "TRUSTED POOL",
      String(c.trusted),
      html`<div class="counter-note">
        random draw active at ${TRUSTED_POOL_SWITCH}
      </div>`,
    )}
    ${counter(
      "HEAD",
      c.sealedHead === null ? "—" : String(c.sealedHead),
      head,
    )}
  </div>`;
}

/** One row of the latest-entries table. Every cell that identifies the entry links to it. */
function latestRow(row: EntryRow): Safe {
  return html`<tr class="row">
    <td class="dim">
      <a href="/entries/${row.id}">${row.position}</a>${row.sealed
        ? raw("")
        : html` <span class="warn">unsealed</span>`}
    </td>
    <td>${badge(statusClass(row.status), row.status)}</td>
    <td>${row.subject}</td>
    <td class="prose">${claimCell(row)}</td>
    <td class="muted">${row.tier ?? "—"}</td>
    <td class="dim">${fmtDate(row.last_confirmed)}</td>
  </tr>`;
}

function latest(rows: EntryRow[]): Safe {
  if (rows.length === 0) {
    return html`<div class="panel-empty">
      Nothing has been submitted yet.
    </div>`;
  }
  return html`<div class="table-wrap">
    <table class="dense">
      <thead>
        <tr>
          <th>pos</th>
          <th>status</th>
          <th>subject</th>
          <th>claim</th>
          <th>tier</th>
          <th>confirmed</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(latestRow)}
      </tbody>
    </table>
  </div>`;
}

/** One of the three ways to read: a title, the command, and what comes back. */
function way(title: string, command: Safe, note: string): Safe {
  return html`<section class="panel">
    <div class="panel-body">
      <h2>${title}</h2>
      ${command}
      <p class="note muted">${note}</p>
    </div>
  </section>`;
}

export function renderHome(ctx: PageContext, data: HomeData): string {
  const from = data.counters.sealedHead ?? 0;
  const example = data.latest[0]?.id ?? "<entry-id>";
  return layout(ctx, {
    title: "Home",
    description:
      "Every fact here carries its proof before a model learns it: one claim, one source, checked by independent operators and sealed into a witnessed log.",
    body: html`
      <div class="cols-side">
        <div class="stack">
          <h1 class="headline">
            Every fact here carries its proof before a model learns it.
          </h1>
          <p class="lede">
            One claim, one primary source, frozen and hashed at submission,
            checked by independent operators, sealed into a witnessed log, and
            dated. Anyone can verify an entry offline with two files and one
            script.
          </p>
          <div class="actions">
            <a class="btn btn-accent" href="/entries">Browse entries</a>
            <a class="btn" href="/api">Read the API</a>
          </div>
        </div>
        <div class="stack">
          ${counters(data.counters)} ${domainLine(data.domain)}
        </div>
      </div>

      <div class="cols-side">
        <section class="panel">
          <div class="panel-head">
            <h2>Latest sealed entries</h2>
            <a class="btn" href="/entries">All entries</a>
          </div>
          ${latest(data.latest)}
        </section>
        <div class="stack">
          ${way(
            "Read one fact",
            html`<pre class="block">GET ${ctx.origin}/read?subject=…&amp;category=…&amp;min_tier=observed</pre>`,
            "Returns the entry, the seal covering it, and a signed read receipt. JSON only: no HTML, no injection surface.",
          )}
          ${way(
            "Sync a learner",
            html`<pre class="block">GET ${ctx.origin}/sync?from=${from}&amp;flatten=true</pre>`,
            "Every sealed event after a position a trainer already holds, each with an inclusion proof, and one signed sync receipt covering the page.",
          )}
          ${way(
            "Verify offline",
            html`<pre class="block">npm run export -- ${ctx.origin} ${example} ./out
npm run verify -- ./out/entry.json ./out/log.json</pre>`,
            "Two files and one script. Exit 0, or a named difference.",
          )}
        </div>
      </div>
    `,
  });
}

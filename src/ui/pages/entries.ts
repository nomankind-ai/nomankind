/**
 * The entries listing: the filters, the dense table, the keyset pager.
 *
 * The filter panel is one GET form and nothing else. There is no script on this
 * page and the content-security-policy forbids one, so a chip is a `<label>`
 * around a hidden radio and "Apply" is a submit button: the browser builds the
 * query string, and the URL a reader ends up at is the whole state of the view.
 * That is what makes a filtered listing something they can bookmark and send to
 * somebody else.
 *
 * The one thing that is not a radio is each group's "all" chip, and the reason
 * is the parser's: `?category=` is a refusal, not an absence (src/ui/query.ts),
 * because a reader who asked for a category and named none made a mistake. A
 * checked radio always submits something, so "all" cannot be one — it is a link
 * that carries the other three filters and drops this one, which is exactly what
 * "no category filter" means as a URL.
 *
 * Decision D-127, the record is free: every entry is released the moment it is
 * sealed, so a keyless reader reads a just-sealed entry's claim here exactly as
 * a keyed one does and the claim column is the claim on every row. Every other
 * column — the position, the status, the subject, the category, the domain, the
 * tier, the dates — is proof or derived from proof and is shown as it always
 * is.
 *
 * Decision D-125, the domain column: the registered domain out of each entry's
 * signed core is read beside its category, on every page and under every filter.
 * The chips stay the filter and the column is the reading — a reader who lands
 * on an unfiltered listing could otherwise only learn a row's domain by opening
 * it, and a reader who arrived from a chip had to trust the chip. Plain text and
 * not a link, because no filter value in this table is one.
 *
 * Decision D-138, the class column and the `min_class` chips: every verified
 * entry discloses who met its consensus — registered, community or mixed — so
 * the listing prints that word per row and takes a floor on it. The chips read
 * weakest first because `min_class` is a minimum everywhere it appears: asking
 * for `mixed` admits `registered` too, exactly as it does on the read and sync
 * doors. A row with no class is a draft or a rejected entry, which has no
 * consensus to have one, and it prints an em dash rather than a word.
 *
 * Pure: the rows, the total and the cursor were all decided by the route.
 */

// The source classes come from the kernel that derives them (src/sources.ts)
// rather than from a list retyped in a page, exactly as the category and domain
// chips come from the schema's own enums: a class added by decision appears as a
// chip in the same commit it becomes a value the sidecar can carry.
import { SOURCE_CLASSES } from "../../sources.js";
// The verification classes come from the policy module that publishes them
// (decision D-138), in its own order — weakest first — for the same reason the
// source classes come from the kernel: the chips are the list, not a copy of it.
import { VERIFICATION_CLASSES } from "../../policy.js";
import {
  ENTRY_CATEGORIES,
  ENTRY_DOMAINS,
  ENTRY_STATUSES,
  ENTRY_TIERS,
  FRESHNESS_VALUES,
} from "../query.js";
import {
  badge,
  fmtDate,
  html,
  layout,
  raw,
  statusClass,
  type Safe,
} from "../html.js";
import type {
  EntriesData,
  EntriesFilter,
  EntryRow,
  PageContext,
} from "../types.js";

/**
 * The six filter parameters, and which field of the filter each reads.
 *
 * `domain` sits where src/ui/query.ts puts it, after status, and `source` sits
 * after `domain`: the order here is the order the chips appear and the order the
 * query string is written in, and two orders for one filter would be two things
 * to keep in step. Their values are the schema's own domain enum and the
 * kernel's own source classes, exactly as the category chips are the schema's
 * categories — never a list retyped in a page.
 */
const GROUPS: readonly {
  readonly name: keyof EntriesFilter;
  readonly values: readonly string[];
}[] = [
  { name: "category", values: ENTRY_CATEGORIES },
  { name: "status", values: ENTRY_STATUSES },
  { name: "domain", values: ENTRY_DOMAINS },
  { name: "source", values: SOURCE_CLASSES },
  { name: "tier", values: ENTRY_TIERS },
  // The floor on who met an entry's consensus (decision D-138). A minimum and
  // not an exact value, so the chips read weakest first and `mixed` admits
  // `registered` too — the same reading `min_class` has on the read and sync
  // doors, because one word must not mean two things.
  { name: "min_class", values: VERIFICATION_CLASSES },
  { name: "fresh", values: FRESHNESS_VALUES },
];

/** A query string, or the empty string when nothing is asked. */
function search(pairs: readonly (readonly [string, string])[]): string {
  if (pairs.length === 0) return "";
  const parts = pairs.map(
    ([name, value]) => `${name}=${encodeURIComponent(value)}`,
  );
  return `?${parts.join("&")}`;
}

/** The filter as query pairs, optionally with one group left out. */
function filterPairs(
  filter: EntriesFilter,
  without?: keyof EntriesFilter,
): (readonly [string, string])[] {
  const pairs: (readonly [string, string])[] = [];
  for (const group of GROUPS) {
    if (group.name === without) continue;
    const value = filter[group.name];
    // Absent and null are one thing here: `min_class` is an optional field of
    // the filter and the other five are always present, so a group nobody asked
    // for carries nothing into the query string either way.
    if (value !== null && value !== undefined) {
      pairs.push([group.name, value]);
    }
  }
  return pairs;
}

/** One group of chips: the "all" link, then one label-wrapped radio per value. */
function group(
  filter: EntriesFilter,
  name: keyof EntriesFilter,
  values: readonly string[],
): Safe {
  const current = filter[name] ?? null;
  const allClass = current === null ? "chip chip-on" : "chip";
  return html`<div class="filter-row">
    <span class="filter-name">${name}</span>
    <a class="${allClass}" href="/entries${search(filterPairs(filter, name))}"
      >all</a
    >
    ${values.map((value) => {
      const chipClass = current === value ? "chip chip-on" : "chip";
      const checked = current === value ? raw(` checked`) : raw("");
      return html`<label class="${chipClass}"
        ><input type="radio" name="${name}" value="${value}"${checked} />${value}</label
      >`;
    })}
  </div>`;
}

/** The whole panel: six groups and the button that applies them. */
function filters(filter: EntriesFilter): Safe {
  return html`<form class="filters" method="get" action="/entries">
    ${GROUPS.map((each) => group(filter, each.name, each.values))}
    <div class="filter-row">
      <span class="filter-name"></span>
      <button class="btn btn-accent" type="submit">Apply</button>
    </div>
  </form>`;
}

/**
 * The claim cell: the claim, linking the entry (D-127, the record is free).
 */
export function claimCell(entry: EntryRow): Safe {
  return html`<a href="/entries/${entry.id}">${entry.claim}</a>`;
}

function row(entry: EntryRow): Safe {
  const expiresClass = entry.stale ? "warn" : "dim";
  return html`<tr class="row">
    <td class="dim">
      <a href="/entries/${entry.id}">${entry.position}</a>${entry.sealed
        ? raw("")
        : html` <span class="warn">unsealed</span>`}
    </td>
    <td>${badge(statusClass(entry.status), entry.status)}</td>
    <td>${entry.subject}</td>
    <td class="muted">${entry.category}</td>
    <td class="muted">${entry.domain === "" ? "—" : entry.domain}</td>
    <td class="prose">${claimCell(entry)}</td>
    <td class="muted">${entry.tier ?? "—"}</td>
    <td class="muted">${entry.verification_class ?? "—"}</td>
    <td class="dim">${fmtDate(entry.last_confirmed)}</td>
    <td class="${expiresClass}">${fmtDate(entry.expires_at)}</td>
  </tr>`;
}

function table(rows: EntryRow[]): Safe {
  if (rows.length === 0) {
    return html`<div class="panel-empty">No entries match these filters.</div>`;
  }
  return html`<div class="table-wrap">
    <table class="dense">
      <thead>
        <tr>
          <th>pos</th>
          <th>status</th>
          <th>subject</th>
          <th>category</th>
          <th>domain</th>
          <th>claim</th>
          <th>tier</th>
          <th>class</th>
          <th>confirmed</th>
          <th>expires</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(row)}
      </tbody>
    </table>
  </div>`;
}

export function renderEntries(ctx: PageContext, data: EntriesData): string {
  const nextHref =
    data.nextBefore === null
      ? null
      : `/entries${search([
          ...filterPairs(data.filter),
          ["before", String(data.nextBefore)] as const,
        ])}`;
  return layout(ctx, {
    title: "Entries",
    description: "Every entry in the log, newest sealed position first.",
    body: html`
      <div class="page-head">
        <h1>Entries</h1>
        <span
          class="mono note"
          title="The total counts every entry with this status and in this domain; the category, source, tier, class and freshness filters narrow the page, not the total."
          >${data.rows.length} of ${data.total} · ordered by sealed
          position</span
        >
      </div>
      ${filters(data.filter)}
      <section class="panel">${table(data.rows)}</section>
      ${nextHref === null
        ? raw("")
        : html`<div class="pager">
            <a class="btn" href="${nextHref}">Next page</a>
          </div>`}
    `,
  });
}

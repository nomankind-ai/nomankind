/**
 * Docs: everything written about the record, in one place (D-104).
 *
 * The pages that explain this system grew one at a time — how it works, the
 * domains, the policy tables, the API, genesis, the dry run, the mirror — and
 * the two documents that specify it lived on GitHub, which meant the answer to
 * "where is this written down" was a list somebody had to know. This page is
 * that list, grouped the way a reader arrives: what the log is, how to join it,
 * and how to leave with it.
 *
 * Three groups and eleven cards, and every card is a page this Worker serves —
 * including the whitepaper and the summary, which are served here now, so
 * nothing about the design lives only in a repository.
 *
 * Pure: the head line's versions are read from src/policy.ts, and nothing here
 * reads a store, a clock or the network.
 */

import { NORM_VERSION, SCHEMA_VERSION } from "../../policy.js";
import { html, layout, type Safe } from "../html.js";
import type { PageContext } from "../types.js";
import { WHITEPAPER_VERSION } from "./document.js";

/** One card: a page, and the one line that says what is on it. */
interface Card {
  readonly href: string;
  readonly title: string;
  readonly line: string;
}

/** One group of cards: a stage number, a title, and the group's own line. */
interface Group {
  readonly number: string;
  readonly title: string;
  readonly note: string;
  readonly cards: readonly Card[];
}

export const DOC_GROUPS: readonly Group[] = Object.freeze([
  Object.freeze({
    number: "01",
    title: "Read the record",
    note: "What the log is and how to read it.",
    cards: Object.freeze([
      Object.freeze({
        href: "/how-it-works",
        title: "How it works",
        line: "The pipeline in ten stages, each linked into this environment's own log.",
      }),
      Object.freeze({
        href: "/domains",
        title: "Domains",
        line: "The three registered domains: what each records, who reads it, who validates it.",
      }),
      Object.freeze({
        href: "/policy",
        title: "Policy",
        line: "Every published number, list, and sentence the rules run on, from the policy module.",
      }),
      Object.freeze({
        href: "/api",
        title: "API",
        line: "Every door: reading with receipts, syncing the delta, keys and tiers, the refusals, the release window.",
      }),
    ]),
  }),
  Object.freeze({
    number: "02",
    title: "Join",
    note: "How an operator gets in, and how to practise first.",
    cards: Object.freeze([
      Object.freeze({
        href: "/genesis",
        title: "Genesis",
        line: "The three joining steps, the attestation, and the dry-run table read from the log.",
      }),
      Object.freeze({
        href: "/dry-run",
        title: "Dry run",
        line: "Practise the joining steps and one validation on demo, command by command.",
      }),
      Object.freeze({
        href: "/operators",
        title: "Operators",
        line: "The directory: who is trusted, in which domains, with what standing.",
      }),
    ]),
  }),
  Object.freeze({
    number: "03",
    title: "Take it with you",
    note: "The exit is a copy, not a promise.",
    cards: Object.freeze([
      Object.freeze({
        href: "/docs/fork",
        title: "Fork guide",
        line: "What to clone, how to verify a mirror, how to keep going without nomankind, and the release window.",
      }),
      Object.freeze({
        // The mockup writes this card's href as /mirror; the page itself is
        // mounted at /mirror/latest and nothing answers /mirror, so the card
        // links the route that exists rather than a 404 with the right name.
        href: "/mirror/latest",
        title: "Mirror",
        line: "The daily export of the sealed log under CC0, and the pointer to today's.",
      }),
      Object.freeze({
        href: "/docs/whitepaper",
        title: "Whitepaper",
        line: `The specification, with every change since ${WHITEPAPER_VERSION} labeled in place.`,
      }),
      Object.freeze({
        href: "/docs/summary",
        title: "Summary",
        line: "The whitepaper in one page.",
      }),
    ]),
  }),
]);

/** One card of a group: the page, its name, and its line. */
function card(each: Card): Safe {
  return html`<a class="step" href="${each.href}"
          ><span class="step-t">${each.title}</span>
          <span class="note">${each.line}</span></a
        >`;
}

/** One group: the numbered heading, the group's line, and its cards. */
function group(each: Group): Safe {
  return html`<section class="panel">
        <h2 class="panel-title">
          <span class="stage-num">${each.number}</span>${each.title}
        </h2>
        <span class="note">${each.note}</span>
        <div class="panel-body">
          <div class="counters">${each.cards.map(card)}</div>
        </div>
      </section>`;
}

export function renderDocs(ctx: PageContext): string {
  return layout(ctx, {
    title: "Docs",
    description:
      "Everything written about the record, in one place: the pages that describe the log, the pages that explain joining it, and the whitepaper, the summary and the fork guide served here rather than only on GitHub.",
    body: html`
      <div class="page-head">
        <h1>Docs</h1>
        <span class="note"
          >whitepaper ${WHITEPAPER_VERSION} with labeled changes · schema
          ${SCHEMA_VERSION} · ${NORM_VERSION}</span
        >
      </div>
      <p class="lede">
        Everything written about the record, in one place. The pages under Read
        the record describe what the log is; Join is how an operator gets in;
        Take it with you is how anyone leaves with the whole thing. The
        whitepaper and the summary are served here too, so nothing about the
        design lives only on GitHub.
      </p>

      <div class="stack">${DOC_GROUPS.map(group)}</div>
    `,
  });
}

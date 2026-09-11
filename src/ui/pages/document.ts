/**
 * One served document: the whitepaper, its summary, or the fork guide (D-104).
 *
 * The three documents are the record of what this thing claims to be, and
 * before this page they lived only on GitHub — so a reader who wanted the
 * specification had to leave the site that is supposed to be the record. Now
 * the Worker serves them from the repository's own bytes, read ahead of time
 * into src/ui/docs.generated.ts and rendered by src/ui/markdown.ts, which emits
 * nothing but the classes in src/ui/styles.ts and escapes every text run.
 *
 * The page around them is the documentation shape the how-it-works and Domains
 * pages use: crumbs, a head with the title and the file the document came from,
 * a strip of the document's own top-level sections as anchors, and then the
 * document in one panel. The strip is a grid that fits its columns to what is
 * in it, exactly as the Domains strip does, because these three documents have
 * five, eight and thirteen sections and one fixed column count would be wrong
 * for two of them.
 *
 * The page prints the title, so the document is rendered under it: every
 * heading one level down, and the document's own opening title dropped where it
 * is the title the page has just printed. That is what keeps one `<h1>` on the
 * page and stops /docs/fork saying "Forking nomankind" twice.
 *
 * Pure: the markdown arrived as a constant, and nothing here reads a store, a
 * clock or the network.
 */

import {
  FORK_MARKDOWN,
  FORK_SOURCE_PATH,
  SUMMARY_MARKDOWN,
  SUMMARY_SOURCE_PATH,
  WHITEPAPER_MARKDOWN,
  WHITEPAPER_SOURCE_PATH,
} from "../docs.generated.js";
import { html, layout, type Safe } from "../html.js";
import { renderMarkdown, sections } from "../markdown.js";
import type { DocumentData, PageContext } from "../types.js";

/**
 * The version of the paper this site serves, named once for every page that
 * says it: the hub's head line and its whitepaper card, this page's note, and
 * the how-it-works head line.
 *
 * Not a policy number: policy is what the record runs on, and this is the
 * version of the document /docs/whitepaper renders. It lives here because this
 * is the module that holds the document itself.
 */
export const WHITEPAPER_VERSION = "v1.5";

/** The directory a document lives in, which its relative links resolve against. */
function directoryOf(path: string): string {
  const cut = path.lastIndexOf("/");
  return cut === -1 ? "" : path.slice(0, cut);
}

/** One cell of the strip across the top, anchored at its own heading. */
function step(id: string, number: string, title: string): Safe {
  return html`<a class="step" href="#${id}"
        ><span class="step-n">${number}</span
        ><span class="step-t">${title}</span></a
      >`;
}

/** The strip: the document's top-level sections, numbered in document order. */
function strip(markdown: string): Safe[] {
  return sections(markdown).map((each, index) =>
    step(each.id, String(index + 1).padStart(2, "0"), each.text),
  );
}

/**
 * The three documents, named once here.
 *
 * The route picks one of these rather than assembling it, so the title a reader
 * sees, the path the page prints and the bytes it renders can never come apart:
 * there is one object per document and it holds all three.
 */
export const FORK_DOCUMENT: DocumentData = Object.freeze({
  title: "Forking nomankind",
  sourcePath: FORK_SOURCE_PATH,
  markdown: FORK_MARKDOWN,
  note: "the exit, in full: what to clone, how to verify it, how to keep going",
});

export const WHITEPAPER_DOCUMENT: DocumentData = Object.freeze({
  title: "Whitepaper",
  sourcePath: WHITEPAPER_SOURCE_PATH,
  markdown: WHITEPAPER_MARKDOWN,
  note: `${WHITEPAPER_VERSION}, with every change since labeled in place`,
});

export const SUMMARY_DOCUMENT: DocumentData = Object.freeze({
  title: "Summary",
  sourcePath: SUMMARY_SOURCE_PATH,
  markdown: SUMMARY_MARKDOWN,
  note: "the whitepaper in one page",
});

export function renderDocument(ctx: PageContext, data: DocumentData): string {
  return layout(ctx, {
    title: data.title,
    description: `${data.note}. Served from ${data.sourcePath} in the code repository, rendered as it is written.`,
    body: html`
      <div class="crumbs mono">
        <a href="/docs">Docs</a><span>/</span><span>${data.title}</span>
      </div>
      <div class="page-head">
        <h1>${data.title}</h1>
        <span class="note"
          >${data.note} · <span class="mono">${data.sourcePath}</span></span
        >
      </div>

      <div class="counters">${strip(data.markdown)}</div>

      <section class="panel">
        <div class="panel-body document">
          ${renderMarkdown(data.markdown, directoryOf(data.sourcePath), {
            underTitle: data.title,
          })}
        </div>
      </section>
    `,
  });
}

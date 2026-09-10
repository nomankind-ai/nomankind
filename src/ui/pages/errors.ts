/**
 * The three refusals a browser can reach.
 *
 * Both name what went wrong in the same word the code used, for the same reason
 * every refusal in this system does: a reader who is told "something went wrong"
 * has learned nothing, and a reader told `bad_category` can fix their URL.
 * No page echoes anything the reader typed except through the escaping in
 * src/ui/html.ts — a 404 that reflected a path unescaped would be the one
 * injection hole in a UI built to have none.
 */

import { html, layout } from "../html.js";
// The list the parser actually accepts, read from the parser rather than
// retyped: a parameter added to one and not the other is a page that tells the
// reader their query is wrong about a filter the listing takes.
import { ENTRIES_QUERY_PARAMETERS } from "../query.js";
import type { PageContext } from "../types.js";

/** Nothing lives at this path. */
export function renderNotFound(ctx: PageContext): string {
  return layout(ctx, {
    title: "Not found",
    description: "No page at this address.",
    body: html`
      <div class="page-head"><h1>Not found</h1></div>
      <p class="lede">
        Nothing is served at this address. An entry id that has never been
        submitted, an operator that has never registered, and a path that was
        never a page all land here.
      </p>
      <p class="note mono">${ctx.path}</p>
      <div class="actions">
        <a class="btn btn-accent" href="/entries">Browse entries</a>
        <a class="btn" href="/api">Read the API</a>
      </div>
    `,
  });
}

/**
 * The query was refused. `reason` is the refusal word from
 * src/ui/query.ts — shown in mono, because it is an identifier and not prose.
 */
export function renderBadQuery(ctx: PageContext, reason: string): string {
  return layout(ctx, {
    title: "Bad query",
    description: "The query was refused.",
    body: html`
      <div class="page-head"><h1>Bad query</h1></div>
      <p class="lede">
        This listing refuses a query it does not understand rather than quietly
        ignoring the part it cannot read: a filter that was dropped instead of
        refused would hand back a list the reader believes is narrower than it is.
      </p>
      <dl class="kv">
        <dt>reason</dt>
        <dd>${reason}</dd>
        <dt>path</dt>
        <dd>${ctx.path}</dd>
      </dl>
      <p class="note">
        Accepted parameters: ${ENTRIES_QUERY_PARAMETERS.join(", ")}. Each may
        appear once, each enum value comes from the entry schema, and
        <span class="mono">before</span> is a sealed position.
      </p>
      <div class="actions">
        <a class="btn btn-accent" href="/entries">All entries</a>
      </div>
    `,
  });
}

/**
 * Storage is unreachable (503).
 *
 * The same refusal the JSON doors answer, in the same word, as a page: a reader
 * who was handed `storage_unreachable` as raw JSON learned that the site is
 * broken and nothing about whether the log is. This says which part failed and
 * which part could not have — the record itself is a hash chain in a sealed log
 * and is not what went missing — and it names no binding. The retry link is the
 * request's own path, which reaches the page only through the escaping in
 * src/ui/html.ts, exactly as the 404's does.
 */
export function renderUnavailable(ctx: PageContext): string {
  return layout(ctx, {
    title: "Unavailable",
    description: "The log's storage is unreachable.",
    body: html`
      <div class="page-head"><h1>Unavailable</h1></div>
      <p class="lede">
        This page could not be read: the log's storage is unreachable. Nothing
        was written and nothing was lost — the record is a sealed hash chain, and
        a read that fails leaves it exactly as it was. Try again.
      </p>
      <p class="note mono">storage_unreachable</p>
      <p class="note">
        Every JSON door answers the same word with the same 503, so an agent and
        a reader are told the same thing about the same failure.
      </p>
      <div class="actions">
        <a class="btn btn-accent" href="${ctx.path}">Try again</a>
        <a class="btn" href="/api">Read the API</a>
      </div>
    `,
  });
}

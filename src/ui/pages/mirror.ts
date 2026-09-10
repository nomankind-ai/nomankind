/**
 * Mirror: the day's export of the sealed log, and how to check it without us.
 *
 * Whitepaper Section 11: the log is mirrored daily to a public repository under
 * CC0, and exit is a protocol right rather than a promise — a fork that clones
 * the mirror and runs the offline verifier has the record, and nothing on this
 * page is needed to read it afterwards. So the page is mostly two things: what
 * was exported last, and the commands that check it.
 *
 * Nothing here is probed when a reader opens it. `latest` is the row the sweep
 * wrote when it pushed, so the page says what this instance exported and never
 * what the repository looks like at this instant, which is a thing only the
 * repository can say. An environment that cannot push says so in words: not
 * configured is not a failure, and an empty panel would report one.
 *
 * Pure, like every page in src/ui/pages/: no clock, no database, no network.
 */

import { fmtDate, fmtInstant, html, layout, link, type Safe } from "../html.js";
import type { MirrorData, PageContext } from "../types.js";

/** The fork documentation, in the code repository beside the code it describes. */
const FORK_DOC_URL =
  "https://github.com/nomankind-ai/nomankind/blob/main/docs/FORK.md";

/** One labelled field of the export record. */
function field(name: string, value: Safe): Safe {
  return html`<div class="field">
              <span class="field-name">${name}</span>
              <span class="field-value">${value}</span>
            </div>`;
}

/**
 * The Latest export panel.
 *
 * Two empty states and one full one, and they are different facts: an
 * environment with no mirror adapter has nothing to say about exports, and an
 * environment that has one but has not run yet is owed its first export by the
 * next sweep after midnight. A page that showed the same sentence for both
 * would be hiding which of the two a reader is looking at.
 */
function latest(data: MirrorData): Safe {
  if (!data.configured) {
    return html`<div class="panel-empty">
          The mirror is not configured on this environment: no export is pushed
          from here, and no export is owed. The repository below is still the
          record — another environment writes it, under its own directory.
        </div>`;
  }
  const record = data.latest;
  if (record === null) {
    return html`<div class="panel-empty">
          No export yet; the first sweep after 00:00 UTC makes one. The sweep
          exports once per UTC day, right after it anchors the previous day.
        </div>`;
  }

  const commit = link(record.url, record.commit, true);
  const rawLink = link(record.raw_url, "mirror.json", true);

  return html`<div class="panel-body">
            <div class="grid-4">
              ${field("date", html`${fmtDate(record.date)}`)}
              ${field("exported_at", html`${fmtInstant(record.exported_at)}`)}
              ${field("head", html`${record.head}`)}
              ${field("seal_seq", html`${record.seal_seq}`)}
              ${field("entries", html`${record.entries}`)}
              ${field("files_changed", html`${record.files_changed}`)}
              ${field("commit", commit)} ${field("tree", html`${record.tree}`)}
            </div>
            <p class="note">
              The export is the sealed record and nothing else: an event that no
              seal covers is not in it, because an unsealed event has no
              inclusion proof to check it by. Read the export's own header at
              ${rawLink}, which carries the counts, the sealed head, the schema
              and normalization versions, and the verify command.
            </p>
          </div>`;
}

export function renderMirror(ctx: PageContext, data: MirrorData): string {
  const repository = link(data.repository, data.repository, true);
  const forkDoc = link(FORK_DOC_URL, "docs/FORK.md", true);

  return layout(ctx, {
    title: "Mirror",
    description:
      "The daily export of the sealed log to a public repository under CC0, and the commands that verify a fresh clone of it.",
    body: html`
      <div class="page-head">
        <h1>Mirror</h1>
        <span class="note"
          >${data.kind} · <a href="/mirror/latest" class="mono"
            >GET /mirror/latest</a
          >
          answers this record as JSON</span
        >
      </div>
      <p class="lede">
        Once per UTC day the sweep exports the sealed log — every entry, event,
        hash, seal, anchor and index — to ${repository} under CC0. Leaving is a
        protocol right and not a favour: a clone of that repository and the
        offline verifier are the whole record, and neither of them needs this
        site to keep working. This environment writes the
        <span class="mono">${data.path}</span> directory of the
        <span class="mono">${data.branch}</span> branch, and touches nothing
        else in it.
      </p>

      <section class="panel">
        <div class="panel-head">
          <h2>Latest export</h2>
          <span class="panel-label">as the sweep recorded it, not as the repository answers now</span>
        </div>
        ${latest(data)}
      </section>

      <div class="cols">
        <section class="panel">
          <h2 class="panel-title">Verify a clone</h2>
          <div class="panel-body">
            <p class="prose">
              Clone the mirror, then run the verifier over this environment's
              directory. It checks the event chain, every seal and its root,
              every anchor, and then each entry against the log it came from —
              the same checks the offline verifier makes on a single exported
              entry, over the whole export at once.
            </p>
            <pre class="block mono">git clone ${data.repository}
npm run verify-mirror -- ../log/${data.path}</pre>
            <p class="prose">
              The verifier fetches the captures an entry's snapshot hashes point
              at from this environment's archive by default, or reads them from a
              local directory with <span class="mono">--captures</span>;
              <span class="mono">--entry</span> checks one entry rather than all
              of them. It exits 0 when nothing failed and 1 on the first named
              failure, and it prints one line per entry either way.
            </p>
          </div>
        </section>
        <section class="panel">
          <h2 class="panel-title">Keeping going without nomankind</h2>
          <div class="panel-body">
            <p class="prose">
              ${forkDoc} says what to clone, how to verify it, and how to run the
              code on your own account with your own keys. The data is CC0 and
              always was: the mirror is a convenience, not the licence, and the
              same record can be pulled from this API by anyone who would rather
              not trust a repository either.
            </p>
            <p class="prose">
              Snapshots are not in the mirror, only their hashes. The captured
              bytes are served from the archive here and may be withdrawn on a
              takedown; the hash stays in the sealed record, so a withdrawn
              capture is visibly a withdrawn capture and never a quietly changed
              one.
            </p>
            <p class="note">
              The export writes only under
              <span class="mono">${data.path}/</span>: the repository's licence,
              its README and the other environment's directory are left exactly
              as they are, so two environments can share one mirror without
              either overwriting the other.
            </p>
          </div>
        </section>
      </div>
    `,
  });
}

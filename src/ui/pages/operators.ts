/**
 * The registry: who may validate, and who is trusted.
 *
 * Section 5, the operator is the unit of accountability, so this is a directory
 * of operators and not of keys: the agent count is what an operator answers for,
 * and the validation count is what its agents have signed. Section 10 and D-016:
 * the maintainer's own operator is registered like any other and may not
 * validate, and the page says so on its row rather than leaving a reader to work
 * it out from the flag.
 *
 * Two columns are honest blanks. Standing is derived by a published formula that
 * M21 has not published yet, and the overturned count needs the dispute door M20
 * builds. A number invented here would be a number nobody can recompute, which
 * is the one thing this log is against, so each says which milestone it waits on.
 *
 * Pure: the rows were gathered by the route.
 */

import { html, layout, type Safe } from "../html.js";
import type { OperatorRow, OperatorsData, PageContext } from "../types.js";

/** The two columns nothing can compute yet, and the milestone that will. */
const NOT_PUBLISHED_STANDING = "not yet published (M21)";
const NOT_PUBLISHED_OVERTURNED = "not yet published (M20)";

const EM_DASH = "—";

function row(operator: OperatorRow): Safe {
  const trustedClass = operator.trusted ? "accent" : "dim";
  return html`<tr class="row">
    <td><a href="/operators/${operator.id}">${operator.id}</a></td>
    <td class="${trustedClass}">
      ${operator.trusted
        ? html`trusted · seq
          ${operator.trustedSeq === null ? EM_DASH : operator.trustedSeq}`
        : html`no`}
    </td>
    <td class="warn">${operator.maintainer ? "cannot validate" : EM_DASH}</td>
    <td class="muted">${operator.provider ? "provider" : EM_DASH}</td>
    <td>${operator.agents}</td>
    <td>${operator.validations}</td>
    <td class="dim">${NOT_PUBLISHED_STANDING}</td>
    <td class="dim">${NOT_PUBLISHED_OVERTURNED}</td>
  </tr>`;
}

export function renderOperators(ctx: PageContext, data: OperatorsData): string {
  return layout(ctx, {
    title: "Operators",
    description: "Every registered operator, and who is in the trusted pool.",
    body: html`
      <div class="page-head">
        <h1>Operators</h1>
        <span class="mono note"
          >${data.rows.length} registered · ordered by id</span
        >
      </div>
      <p class="lede">
        A verified legal entity behind one or more agent keys. Only registered
        operators validate; only those the log has trusted are drawn from the
        trusted pool. No model provider may register, and the maintainer's own
        operator may not validate.
      </p>
      <section class="panel">
        ${data.rows.length === 0
          ? html`<div class="panel-empty">
              No operator has registered yet.
            </div>`
          : html`<div class="table-wrap">
              <table class="dense">
                <thead>
                  <tr>
                    <th>operator</th>
                    <th>trusted</th>
                    <th>maintainer</th>
                    <th>provider</th>
                    <th>agents</th>
                    <th>validations</th>
                    <th>standing</th>
                    <th>overturned</th>
                  </tr>
                </thead>
                <tbody>
                  ${data.rows.map(row)}
                </tbody>
              </table>
            </div>`}
      </section>
      <p class="note">
        Standing and the overturned count are derived from the sealed events by
        published formulas, and anyone can recompute them once those formulas are
        published.
      </p>
    `,
  });
}

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
 * The standing column is now a reading like every other (Section 9): the number
 * the published formula returned, shown with the log position it was computed
 * at, because a standing without its position is a number nobody can recompute.
 * An operator the formula has not been run for yet shows a dash rather than a
 * zero — nothing computed and nothing earned are different facts. The overturned
 * count beside it is a reading too: the entries an operator signed, as submitter
 * or as approver, that an upheld dispute overturned, counted once per entry.
 *
 * Pure: the rows were gathered by the route.
 */

import { html, layout, type Safe } from "../html.js";
import type { OperatorRow, OperatorsData, PageContext } from "../types.js";

const EM_DASH = "—";

/**
 * The standing cell: the integer, and the position it was computed at in the
 * title, so a reader can rerun the formula over the log up to that position and
 * check the number. A dash when nothing has been computed for this operator.
 */
function standingCell(operator: OperatorRow): Safe {
  const cached = operator.standing;
  if (cached === null) return html`<td class="dim">${EM_DASH}</td>`;
  return html`<td title="computed at position ${cached.seq}">
      ${cached.standing}
    </td>`;
}

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
    ${standingCell(operator)}
    <td class="${operator.overturned === 0 ? "dim" : "danger"}">
      ${operator.overturned}
    </td>
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
        Standing is derived from the sealed events by the published formula on
        the policy page, so anyone can recompute it and get the same number; each
        cell carries the log position it was computed at, and a dash means the
        formula has not been run for that operator yet rather than that it has
        earned nothing. The overturned count beside it is a reading of the log
        too: entries this operator signed, as submitter or as approver, that an
        upheld dispute overturned.
      </p>
    `,
  });
}

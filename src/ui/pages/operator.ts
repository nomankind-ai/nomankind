/**
 * One operator: its agents, its attestation, its validations.
 *
 * Section 11's three joining steps, read back: the domain that registered, the
 * agent keys bound under it, and the signed independence attestation Section 10
 * requires. The attestation is shown as what was signed — version, instant,
 * signature — because that is what an offline reader rechecks it from; the page
 * neither verifies it nor claims it verified.
 *
 * Pure: the route gathered all of it.
 */

import { fmtInstant, html, layout, type Safe } from "../html.js";
import type { OperatorData, PageContext } from "../types.js";

const EM_DASH = "—";

function attestation(record: Record<string, unknown> | null): Safe {
  if (record === null) {
    return html`<div class="panel-empty">
      No attestation is stored on this row.
    </div>`;
  }
  const value = (key: string): string => {
    const found = record[key];
    return typeof found === "string" && found !== "" ? found : EM_DASH;
  };
  return html`<div class="panel-body">
    <dl class="kv">
      <dt>version</dt>
      <dd>${value("version")}</dd>
      <dt>signed_at</dt>
      <dd>${fmtInstant(value("signed_at"))}</dd>
      <dt>signature</dt>
      <dd class="break">${value("signature")}</dd>
    </dl>
    <p class="note">
      The signature is over the attestation text this environment publishes on
      the genesis page; a reader rechecks it against the operator's own agent
      key.
    </p>
  </div>`;
}

function validations(data: OperatorData): Safe {
  if (data.validations.length === 0) {
    return html`<div class="panel-empty">
      This operator has signed no decisions.
    </div>`;
  }
  return html`<div class="table-wrap">
    <table class="dense">
      <thead>
        <tr>
          <th>entry</th>
          <th>decision</th>
          <th>signed_at</th>
          <th>seq</th>
        </tr>
      </thead>
      <tbody>
        ${data.validations.map(
          (each) => html`<tr class="row">
            <td><a href="/entries/${each.entryId}">${each.entryId}</a></td>
            <td class="${each.decision === "approve" ? "accent" : "danger"}">
              ${each.decision}
            </td>
            <td class="dim">${fmtInstant(each.signed_at)}</td>
            <td class="dim">${each.seq}</td>
          </tr>`,
        )}
      </tbody>
    </table>
  </div>`;
}

export function renderOperator(ctx: PageContext, data: OperatorData): string {
  const row = data.row;
  const flags: string[] = [];
  if (row.maintainer) flags.push("maintainer · cannot validate");
  if (row.provider) flags.push("provider");
  if (row.trusted) flags.push("trusted");

  return layout(ctx, {
    title: row.id,
    description: `The registry record for ${row.id}.`,
    body: html`
      <div class="crumbs mono">
        <a href="/operators">Operators</a><span>/</span><span>${row.id}</span>
      </div>
      <div class="page-head">
        <h1>${row.id}</h1>
        <span class="mono note"
          >${row.agents} agents · ${row.validations} validations</span
        >
      </div>

      <div class="cols">
        <section class="panel">
          <div class="panel-head"><h2>Record</h2></div>
          <div class="panel-body">
            <dl class="kv">
              <dt>id</dt>
              <dd>${row.id}</dd>
              <dt>flags</dt>
              <dd>${flags.length === 0 ? EM_DASH : flags.join(" · ")}</dd>
              <dt>registered seq</dt>
              <dd>${row.registeredSeq}</dd>
              <dt>trusted seq</dt>
              <dd>${row.trustedSeq === null ? EM_DASH : row.trustedSeq}</dd>
              <dt>named by</dt>
              <dd class="break">${data.namedBy ?? EM_DASH}</dd>
              <dt>payout status</dt>
              <dd>${data.payoutStatus ?? EM_DASH}</dd>
            </dl>
          </div>
        </section>
        <section class="panel">
          <div class="panel-head">
            <h2>Attestation</h2>
            <span class="panel-label">signed to register</span>
          </div>
          ${attestation(data.attestation)}
        </section>
      </div>

      <section class="panel">
        <div class="panel-head">
          <h2>Agents</h2>
          <span class="panel-label"
            >every agent under an operator counts as one</span
          >
        </div>
        ${data.agents.length === 0
          ? html`<div class="panel-empty">No agent is bound.</div>`
          : html`<div class="panel-body mono">
              ${data.agents.map(
                (agent) => html`<div class="break">${agent}</div>`,
              )}
            </div>`}
      </section>

      <section class="panel">
        <div class="panel-head"><h2>Validations</h2></div>
        ${validations(data)}
      </section>
    `,
  });
}

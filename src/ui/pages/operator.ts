/**
 * One operator: its agents, its attestation, its validations.
 *
 * Section 11's three joining steps, read back: the domain that registered, the
 * agent keys bound under it, and the signed independence attestation Section 10
 * requires. The attestation is shown as what was signed — version, instant,
 * signature — because that is what an offline reader rechecks it from; the page
 * neither verifies it nor claims it verified.
 *
 * The overturned count in the record block is the same reading the directory
 * shows (Section 6): entries this operator signed that an upheld dispute
 * overturned, counted once per entry.
 *
 * Two panels are the money and standing sides of Section 9. Standing shows the
 * number the published formula returned and the position it returned it at, and
 * says in the same breath that anyone can recompute it — with the endpoint that
 * serves it and the command that checks it, because a claim of recomputability
 * that does not say how is not one. The Ledger panel shows what the rows add up
 * to and the rows themselves; every amount is the integer the ledger stores,
 * with a dollar rendering beside it, and no amount is rounded on the way.
 *
 * Section 8's drift attestation is the last panel, from both sides: what this
 * operator's own model was asked, and what this operator was drawn to score.
 * The two are separate tables because they are separate relationships, and the
 * whole construction turns on the scorers being outside the model's operator.
 *
 * Pure: the route gathered all of it, the balance included.
 */

import type { LedgerRow } from "../../ledger.js";
import {
  badge,
  fmtDate,
  fmtInstant,
  html,
  layout,
  shortHash,
  type Safe,
} from "../html.js";
import type { AttestationRow, OperatorData, PageContext } from "../types.js";

const EM_DASH = "—";

/**
 * Micro-USD per dollar. A unit and not a policy number: the ledger counts in
 * millionths of a dollar (src/ledger.ts) and this is what a millionth means.
 */
const MICROS_PER_DOLLAR = 1_000_000;

/**
 * A micro-USD amount as dollars, by integer arithmetic only.
 *
 * Never a float: a share of a day's reads is exact in micros and a division that
 * went through a double would show a reader a number the ledger does not hold.
 * Six decimals, because that is how many the unit has, and a sign in front
 * rather than around, because a clawback is a negative row.
 */
function dollars(micros: number): string {
  const negative = micros < 0;
  const magnitude = negative ? -micros : micros;
  const whole = Math.trunc(magnitude / MICROS_PER_DOLLAR);
  const fraction = magnitude % MICROS_PER_DOLLAR;
  return `${negative ? "-" : ""}$${whole}.${String(fraction).padStart(6, "0")}`;
}

/** One amount, in the unit its own row was written in. */
function amount(row: LedgerRow): Safe {
  if (row.unit === "micros") {
    return html`${row.amount} <span class="dim">${dollars(row.amount)}</span>`;
  }
  return html`${row.amount} <span class="dim">${row.unit}</span>`;
}

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

/**
 * Standing (Section 9), and how to check it.
 *
 * The number is the cache and the position is what makes it checkable: fold the
 * sealed events up to that position by the published formula and the same number
 * has to come back. The endpoint recomputes it over the log rather than reading
 * the column, and the command below asks the endpoint and folds the events
 * itself, so the two answers can be compared by anyone who has neither.
 */
function standingPanel(ctx: PageContext, data: OperatorData): Safe {
  const cached = data.row.standing;
  const id = data.row.id;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Standing</h2>
      <span class="panel-label">recomputable by anyone</span>
    </div>
    ${cached === null
      ? html`<div class="panel-empty">
          No standing has been computed for this operator yet. That is not a
          standing of zero: the formula has simply not been folded over the log
          for it, and the endpoint below computes it on demand.
        </div>`
      : html`<div class="panel-body">
          <dl class="kv">
            <dt>standing</dt>
            <dd>${cached.standing}</dd>
            <dt>computed at</dt>
            <dd>position ${cached.seq}</dd>
          </dl>
        </div>`}
    <p class="note">
      Standing is not a score nomankind assigns. It is derived from the sealed
      public events by the formula published on the policy page, so anyone can
      recompute anyone's standing from the log and get the same number. The
      number above is a cache of that computation at the position beside it, and
      the log is what decides if the two ever disagree.
    </p>
    <p class="note">
      <span class="mono">GET /operators/${id}/standing</span> recomputes it over
      the sealed log and answers with the earned and burned totals, what open
      stakes have locked, the counts behind each, and the formula's own term
      names. The command folds the events itself and compares.
    </p>
    <pre class="block mono">npm run standing -- ${ctx.origin} ${id}</pre>
  </section>`;
}

/** One ledger row's entry cell: a link when the row is about an entry. */
function entryCell(row: LedgerRow): Safe {
  if (row.entry_id === null) return html`<td class="dim">${EM_DASH}</td>`;
  return html`<td class="break">
      <a href="/entries/${row.entry_id}">${row.entry_id}</a>
    </td>`;
}

/**
 * The money (Section 9), in the unit the ledger counts in.
 *
 * The balance is the route's, computed by `ledgerBalance` over exactly the rows
 * shown and at the route's own clock, so held and released mean what they mean
 * at the instant the page was answered and not at some later reading. `paid`
 * against a row is a fact off the payouts themselves: a payout names the row ids
 * it covered, so a row is paid when a payout says it is.
 */
function ledgerPanel(data: OperatorData): Safe {
  const paidRowIds = new Set<string>();
  for (const payout of data.payouts) {
    const covered = payout.ref["rows"];
    if (!Array.isArray(covered)) continue;
    for (const id of covered) {
      if (typeof id === "string") paidRowIds.add(id);
    }
  }

  const balance = data.balance;
  const totals: readonly { readonly name: string; readonly value: number }[] = [
    { name: "accrued", value: balance.accrued },
    { name: "held", value: balance.held },
    { name: "released", value: balance.released },
    { name: "clawed_back", value: balance.clawed_back },
    { name: "paid", value: balance.paid },
    { name: "carried_forward", value: balance.carried_forward },
  ];

  return html`<section class="panel">
    <div class="panel-head">
      <h2>Ledger</h2>
      <span class="panel-label">micro-USD, a millionth of a dollar</span>
    </div>
    ${data.ledger.length === 0
      ? html`<div class="panel-empty">
          Nothing has been recorded against this operator: no read share, no
          bounty, no stake and no payout.
        </div>`
      : html`<div class="panel-body">
            <div class="grid-4">
              ${totals.map(
                (total) => html`<div class="field">
                  <span class="field-name">${total.name}</span>
                  <span class="field-value"
                    >${total.value}
                    <span class="dim">${dollars(total.value)}</span></span
                  >
                </div>`,
              )}
            </div>
          </div>
          <div class="table-wrap">
            <table class="dense">
              <thead>
                <tr>
                  <th>kind</th>
                  <th>entry</th>
                  <th>role</th>
                  <th>date</th>
                  <th>amount</th>
                  <th>available_at</th>
                  <th>paid</th>
                </tr>
              </thead>
              <tbody>
                ${data.ledger.map(
                  (row) => html`<tr class="row">
                    <td>${row.kind}</td>
                    ${entryCell(row)}
                    <td class="dim">${row.role ?? EM_DASH}</td>
                    <td class="dim">${fmtDate(row.date)}</td>
                    <td class="${row.amount < 0 ? "danger" : ""}">
                      ${amount(row)}
                    </td>
                    <td class="dim">${fmtInstant(row.available_at)}</td>
                    <td class="${paidRowIds.has(row.id) ? "accent" : "dim"}">
                      ${paidRowIds.has(row.id) ? "paid" : EM_DASH}
                    </td>
                  </tr>`,
                )}
              </tbody>
            </table>
          </div>`}
    <p class="note">
      Every row but a payout is a function of the sealed log: the read counts the
      log published, the split on the policy page, and the holdback the same page
      names. A payout records money that left through a provider under its own
      reference, which is the one thing replaying the log cannot reproduce, and
      it names the rows it covered so both sides can be reconciled.
    </p>
  </section>`;
}

/**
 * The badge class for an attestation's status.
 *
 * Four states and three readings: one still running (open, answered), one
 * finished (scored), one that ran out of time (expired). An expired attestation
 * is not a bad score and is not shown as one — nobody scored it, which is a
 * different fact from a low score and reads differently here.
 */
function attestationStatusClass(status: string): string {
  switch (status) {
    case "open":
      return "b-open";
    case "answered":
      return "b-answered";
    case "scored":
      return "b-scored";
    default:
      return "b-expired";
  }
}

/**
 * One attestation row. The model is an agent id, shortened the way every hash
 * on these pages is shortened, with the whole of it in the title: a key a
 * reader cannot copy in full is a key they cannot check.
 */
function attestationRow(row: AttestationRow): Safe {
  return html`<tr class="row">
    <td class="break">${row.id}</td>
    <td class="muted" title="${row.model}">${shortHash(row.model)}</td>
    <td>${badge(attestationStatusClass(row.status), row.status)}</td>
    <td>
      ${row.score === null
        ? html`<span class="dim">${EM_DASH}</span>`
        : html`${row.score.agreed} / ${row.score.probe_count}`}
    </td>
    <td class="dim">${row.date === null ? EM_DASH : fmtDate(row.date)}</td>
    <td class="muted" title="${row.probe_hash}">${shortHash(row.probe_hash)}</td>
  </tr>`;
}

/** One of the two attestation tables, or the words for an empty one. */
function attestationTable(
  title: string,
  empty: string,
  rows: readonly AttestationRow[],
): Safe {
  if (rows.length === 0) {
    return html`<div class="panel-body"><h3 class="mono">${title}</h3></div>
      <div class="panel-empty">${empty}</div>`;
  }
  return html`<div class="panel-body"><h3 class="mono">${title}</h3></div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>id</th>
            <th>model</th>
            <th>status</th>
            <th>score</th>
            <th>date</th>
            <th>probe_hash</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(attestationRow)}
        </tbody>
      </table>
    </div>`;
}

/**
 * Drift attestation, from both sides (Section 8, Drift attestation).
 *
 * Two tables and not one, because they are two different relationships: the
 * attestations this operator's own model asked for, and the ones this operator
 * was drawn to score. The separation is the paper's — the scorers are "parties
 * its lab does not control" — so running the two together on one page would
 * hide exactly the thing the construction exists to show.
 *
 * A score is two numbers, agreed over probe_count, and never the fraction:
 * three of three at genesis and thirty of thirty later are not the same claim,
 * and the page leaves the weighting to the reader for the same reason the
 * confidence field is null.
 */
function attestationsPanel(data: OperatorData): Safe {
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Attestations</h2>
      <span class="panel-label">probes drawn by the beacon, scored by others</span>
    </div>
    ${attestationTable(
      "As the model's operator",
      "No attestation has been requested for a model under this operator.",
      data.attestations.asModel,
    )}
    ${attestationTable(
      "As a scorer",
      "This operator has not been drawn to score an attestation.",
      data.attestations.asScorer,
    )}
    <p class="note">
      An attestation says one thing in public: as of its date, this model's
      answers to a probe set drawn by public randomness agreed with the verified
      record to this degree, judged by trusted operators the model's own
      operator does not control. The score is agreed over the number of probes
      asked, because a score over a thin probe set is a small claim and never a
      confident one.
    </p>
  </section>`;
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
              <dt>overturned</dt>
              <dd class="${row.overturned === 0 ? "" : "danger"}">
                ${row.overturned}
              </dd>
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

      ${standingPanel(ctx, data)} ${ledgerPanel(data)}
      ${attestationsPanel(data)}

      <section class="panel">
        <div class="panel-head"><h2>Validations</h2></div>
        ${validations(data)}
      </section>
    `,
  });
}

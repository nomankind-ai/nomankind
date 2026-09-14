/**
 * Independence: the two sets, what falls between them, and what each signature
 * covers (decision D-121).
 *
 * Whitepaper "Limitations" ("The identity layer is young"): the seal is exactly
 * as unrewritable as the countersigners are independent. The page exists
 * because two readers of the 1F916 board asked the same thing in two ways —
 * commonwealth, who runs pinned witness 6, pointed out that a countersignature
 * covers a registry head and never an individual event, and that a witness set
 * drawn from the validators is the failure a witness set exists to catch;
 * morty-synctzn asked the record to publish both sets and say what object each
 * signature is over, in literal field names. So this is both sets, the
 * intersection, and a row per signature kind naming the object and its fields.
 *
 * The page states the comparison it makes rather than implying one, because the
 * honest answer is narrow: the log can see a witness key bound as a registered
 * operator's agent, and it cannot see a shared owner behind two names. That is
 * what the opening paragraph says, and it is the same sentence the paper's
 * Limitations carries — the exclusion is honest, not airtight, and the frames a
 * measurement was taken in are not recorded at all.
 *
 * Pure, like every page in src/ui/pages/: `independenceReport` decided every
 * word below that is a verdict, and this file renders it.
 */

import { html, layout, link, raw, type Safe } from "../html.js";
import {
  CLAIM_SHARED_PERIMETER,
  type IndependenceReport,
  type OverlapEntry,
  type ValidatorEntry,
  type WitnessEntry,
} from "../../independence.js";
import type { IndependenceData, PageContext } from "../types.js";

const EM_DASH = "—";

/** One registered operator: who it is, what it may do, where it is attested. */
function validatorRow(entry: ValidatorEntry): Safe {
  return html`<tr class="row">
    <td><a href="/operators/${entry.operator}">${entry.operator}</a></td>
    <td class="${entry.trusted ? "accent" : "dim"}">
      ${entry.trusted ? "trusted" : "no"}
    </td>
    <td class="warn">${entry.maintainer ? "cannot validate" : EM_DASH}</td>
    <td class="muted">${entry.provider ? "provider" : EM_DASH}</td>
    <td class="mono">
      ${entry.domains.length === 0 ? EM_DASH : entry.domains.join(" · ")}
    </td>
  </tr>`;
}

/**
 * One pinned witness. The head is the point of the row: what this key actually
 * countersigned, as (tree_size, root), read off the newest seal's own record. A
 * witness whose countersignature is in the direct form carries no head at all
 * and the row says so rather than printing a number nothing stored.
 */
function witnessRow(entry: WitnessEntry): Safe {
  const head =
    entry.head === null
      ? entry.counted
        ? html`<span class="dim">no head stored (direct form)</span>`
        : html`<span class="dim">${EM_DASH}</span>`
      : html`tree_size ${entry.head.tree_size}<br /><span class="break"
            >root ${entry.head.root}</span
          >`;
  return html`<tr class="row">
    <td>${entry.id}</td>
    <td class="mono">${entry.operator}</td>
    <td class="mono break">${entry.public_key}</td>
    <td class="${entry.counted ? "accent" : "dim"}">
      ${entry.counted ? "counted" : "none on the newest seal"}
    </td>
    <td class="mono">${head}</td>
    <td class="${entry.bound_operator === null ? "dim" : "danger"}">
      ${entry.bound_operator ?? EM_DASH}
    </td>
  </tr>`;
}

/** One witness that is also in the validator set, and which check found it. */
function overlapRow(entry: OverlapEntry): Safe {
  return html`<tr class="row">
    <td class="mono">${entry.witness}</td>
    <td class="mono break">${entry.agent}</td>
    <td><a href="/operators/${entry.operator}">${entry.operator}</a></td>
    <td class="mono">${entry.matched}</td>
  </tr>`;
}

/** The claim, in the words the rule picked, and what it rests on. */
function claim(report: IndependenceReport): Safe {
  const external =
    report.external_witness_outside_validator_and_subject_provider_control;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>The claim</h2>
      <span class="panel-label">what this record will say out loud</span>
    </div>
    <div class="panel-body">
      <p class="lede">${report.claim}</p>
      <dl class="kv">
        <dt>intersection</dt>
        <dd>
          ${report.intersection.length === 0
            ? raw("empty")
            : html`${report.intersection.length} of
              ${report.witness_set.length} pinned witnesses`}
        </dd>
        <dt>external_witness_outside_validator_and_subject_provider_control</dt>
        <dd class="mono">${external ? "true" : "false"}</dd>
        <dt>read from</dt>
        <dd>
          ${report.seal_seq === null
            ? raw("no seal yet")
            : html`<a href="/seals/${report.seal_seq}"
                >seal ${report.seal_seq}</a
              >`}
        </dd>
      </dl>
      <p class="note">
        The claim is a reading and not a promise: while the intersection is empty
        and at least one pinned witness outside it has a countersignature this
        record counted, the confirmation is external and independent as far as
        the log can see. A non-empty intersection changes the words rather than
        hiding the fact — the keys are still distinct keys, the perimeter they
        share is the table above, and the claim falls back to
        <span class="mono">${CLAIM_SHARED_PERIMETER}</span>. A pinned witness
        that has never countersigned is an intention, so it does not raise the
        flag.
      </p>
    </div>
  </section>`;
}

/** What each kind of signature is over, in the record's own field names. */
function covered(report: IndependenceReport): Safe {
  const rows = Object.entries(report.covered_object).map(
    ([kind, each]) => html`<tr class="row">
      <td class="mono">${kind}</td>
      <td>${each.covers}</td>
      <td class="mono break">${each.fields.join(", ")}</td>
      <td class="muted">${each.signed_by}</td>
      <td class="note">${each.note}</td>
    </tr>`,
  );
  return html`<section class="panel">
    <div class="panel-head">
      <h2>What each signature covers</h2>
      <span class="panel-label">the object, and its literal fields</span>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>kind</th>
            <th>covers</th>
            <th>fields</th>
            <th>signed by</th>
            <th>what that means</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>
  </section>`;
}

export function renderIndependence(
  ctx: PageContext,
  data: IndependenceData,
): string {
  const report = data.report;
  const paper = link("/docs/whitepaper", "Limitations", false);

  return layout(ctx, {
    title: "Independence",
    description:
      "The validator set and the witness set side by side, the intersection of the two, and what object each signature in this record covers.",
    body: html`
      <div class="page-head">
        <h1>Independence</h1>
        <span class="mono note"
          >${report.validator_set.length} operators ·
          ${report.witness_set.length} pinned witnesses ·
          <a href="/independence">GET /independence</a> answers this as JSON</span
        >
      </div>
      <p class="lede">
        A seal this record makes is only as unrewritable as the keys that
        countersign it are independent of the record, so this page publishes both
        sets rather than asserting the bar and stopping: every registered
        operator that may validate, every witness the policy pins, and whether
        any name appears in both. The comparison it makes is narrow on purpose.
        An operator id is a DNS name the registry verified and a witness is a
        1F916 handle with its key inside it, so what the log can honestly check
        is a binding it holds itself — a witness whose key is bound as a
        registered operator's agent, or whose handle is a registered operator's
        own id. A shared owner behind two names, or a contract nobody published,
        is outside what any of this can see: the exclusion is honest, not
        airtight, exactly as the paper's ${paper} says, and the frames a
        measurement was taken in are not recorded at all.
      </p>

      ${claim(report)}

      <section class="panel">
        <div class="panel-head">
          <h2>Validator set</h2>
          <span class="panel-label">every registered operator, trusted or not</span>
        </div>
        ${report.validator_set.length === 0
          ? html`<div class="panel-empty">No operator has registered yet.</div>`
          : html`<div class="table-wrap">
              <table class="dense">
                <thead>
                  <tr>
                    <th>operator</th>
                    <th>trusted</th>
                    <th>maintainer</th>
                    <th>provider</th>
                    <th>domains</th>
                  </tr>
                </thead>
                <tbody>
                  ${report.validator_set.map(validatorRow)}
                </tbody>
              </table>
            </div>`}
        <p class="note">
          Trusted or not, because an operator outside the pool today can be named
          into it tomorrow and a set that showed only the pool would be the
          smaller claim. The full directory, with standing and co-signers, is
          <a href="/operators">the operators page</a>.
        </p>
      </section>

      <section class="panel">
        <div class="panel-head">
          <h2>Witness set</h2>
          <span class="panel-label">WITNESS_PIN, by directory id</span>
        </div>
        ${report.witness_set.length === 0
          ? html`<div class="panel-empty">
              No witness is pinned on this environment.
            </div>`
          : html`<div class="table-wrap">
              <table class="dense">
                <thead>
                  <tr>
                    <th>id</th>
                    <th>operator</th>
                    <th>public key</th>
                    <th>newest seal</th>
                    <th>head countersigned</th>
                    <th>bound to an operator</th>
                  </tr>
                </thead>
                <tbody>
                  ${report.witness_set.map(witnessRow)}
                </tbody>
              </table>
            </div>`}
        <p class="note">
          The bar these are pinned under is on
          <a href="/policy">the policy page</a>: a published key, no two under
          common control, nomankind ineligible to be one, and no pinned witness
          an operator of the record or under the control of one. The head column
          is what that witness actually signed — the registry's tree at a size,
          never this log's event — read off the newest seal's own witness
          records.
        </p>
      </section>

      <section class="panel">
        <div class="panel-head">
          <h2>Intersection</h2>
          <span class="panel-label">names that are in both sets</span>
        </div>
        ${report.intersection.length === 0
          ? html`<div class="panel-empty">
              Empty: no pinned witness is a registered operator of this record,
              by either comparison above.
            </div>`
          : html`<div class="table-wrap">
              <table class="dense">
                <thead>
                  <tr>
                    <th>witness</th>
                    <th>agent</th>
                    <th>operator</th>
                    <th>matched by</th>
                  </tr>
                </thead>
                <tbody>
                  ${report.intersection.map(overlapRow)}
                </tbody>
              </table>
            </div>`}
      </section>

      ${covered(report)}
    `,
  });
}

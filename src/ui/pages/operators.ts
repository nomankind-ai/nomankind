/**
 * The leaderboard: every operator, ranked by standing.
 *
 * Whitepaper Incentives / Standing, as decision D-130 amended it: standing is
 * an asset, "public and named on a leaderboard". So the directory is ordered by
 * the number and not by the id, the rank is printed beside each row, and equal
 * standings share a rank — a leaderboard that broke a tie by alphabet would be
 * publishing an ordering the log does not support.
 *
 * Section 5, the operator is the unit of accountability, so this is still a
 * directory of operators and not of keys: the agent count is what an operator
 * answers for, and the work counts beside it are what its agents have signed.
 * Section 10 and D-016: the maintainer's own operator is registered like any
 * other and may not validate, and the page says so on its row rather than
 * leaving a reader to work it out from the flag.
 *
 * Every number on a row is a reading. The standing is what the published
 * formula returned, shown with the log position it was computed at, because a
 * standing without its position is a number nobody can recompute; the
 * validations, the reproductions and the three marks are the sweep's own
 * accumulator, the counts the same fold was over; and the tier is `tierOf` over
 * that standing, which is what the number actually buys — rate and reach, never
 * truth. An operator the formula has not been run for yet shows a dash rather
 * than a zero: nothing computed and nothing earned are different facts.
 *
 * The marks are small and factual and are never softened (D-127): overturned,
 * missed, forfeits, each a count of sealed events, each one click from the
 * Record on the operator's own page that names them one by one.
 *
 * Pure: the rows were gathered by the route. The ordering and the rank are the
 * one thing computed here, and both are pure functions of the rows.
 */

import { html, layout, type Safe } from "../html.js";
import type { BareKeyRow, OperatorRow, OperatorsData, PageContext } from "../types.js";

const EM_DASH = "—";

/** An operator's row with the place the ordering put it in. */
export interface RankedOperator {
  readonly rank: number;
  readonly operator: OperatorRow;
}

/**
 * The leaderboard's ordering: standing descending, ties sharing a rank.
 *
 * Two rules and no third. An operator with no computed standing sorts below
 * every operator that has one, because a dash is not a number and placing it
 * among them would be inventing one; among themselves those rows keep the order
 * the route read them in. And equal standings share a rank — the second of two
 * operators on twelve is ranked with the first, and the next distinct standing
 * takes the place after both of them, which is what a tie means.
 *
 * Exported so the ordering can be checked without parsing HTML: it is the one
 * derivation this page does.
 */
export function rankOperators(
  rows: readonly OperatorRow[],
): readonly RankedOperator[] {
  const ordered = [...rows].sort((left, right) => {
    const a = left.standing;
    const b = right.standing;
    if (a === null && b === null) return 0;
    if (a === null) return 1;
    if (b === null) return -1;
    return b.standing - a.standing;
  });
  const ranked: RankedOperator[] = [];
  let rank = 0;
  let previous: number | null | undefined;
  ordered.forEach((operator, index) => {
    const standing = operator.standing === null ? null : operator.standing.standing;
    if (previous === undefined || standing !== previous) rank = index + 1;
    previous = standing;
    ranked.push({ rank, operator });
  });
  return ranked;
}

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

/**
 * The kind cell (decision D-138): domain, or community with the account behind
 * it.
 *
 * A community operator's row says what it is bound to rather than only what it
 * is called, because the id is the binding read back — `<venue>:<handle>` — and
 * a reader who is shown the word `community` and nothing else has been told
 * which door it came in by and not who it is.
 */
function kindCell(operator: OperatorRow): Safe {
  const account = operator.community;
  if (account === null) return html`<td class="muted">${operator.kind}</td>`;
  // And what it is bound BY (decision D-142), because since the account rung
  // the word `community` no longer says how strongly: a registry key-bind, a
  // key on a public profile and a board's own authentication of a login are
  // three different things, and a reader scanning the directory should not have
  // to open each row to find out which one it is looking at.
  return html`<td class="muted">
    ${operator.kind}
    <div class="dim mono break">${account.venue} · ${account.handle}</div>
    <div
      class="${account.binding.kind === "account" ? "dim mono warn" : "dim mono"}"
    >
      ${account.binding.kind}-bound
    </div>
  </td>`;
}

/** The domains this operator is attested in, in the order it took them on. */
function domainsCell(operator: OperatorRow): Safe {
  if (operator.domainSlugs.length === 0) {
    return html`<td class="dim">${EM_DASH}</td>`;
  }
  return html`<td class="mono break">${operator.domainSlugs.join(" · ")}</td>`;
}

/**
 * The work counts: the validations this operator's agents completed, and how
 * many of those carried a passing measurement (decision D-087).
 *
 * Volunteered and assigned added together, because the leaderboard's question
 * is how much work was done and not how it was come by; the split is on the
 * operator's own page, under the standing it was folded with.
 */
function workCells(operator: OperatorRow): Safe {
  const counts = operator.counts;
  // Before the fold has ever run for this operator there is still a count of
  // its decisions — the materialised validation counter the sweep's counters
  // step wrote — and that is the number shown, because it is a reading of the
  // same decisions and a dash here would say no work was done. There is no
  // reproduction count without the fold, and that cell dashes.
  if (counts === null) {
    return html`<td>${operator.validations}</td>
      <td class="dim">${EM_DASH}</td>`;
  }
  const validations =
    counts.validations_volunteered + counts.validations_assigned;
  return html`<td>${validations}</td>
    <td class="${counts.validations_reproduced === 0 ? "dim" : "accent"}">
      ${counts.validations_reproduced}
    </td>`;
}

/**
 * The three marks, as counters and nothing more (D-130).
 *
 * Overturned, missed, forfeits: each one a count of sealed events, printed
 * small, with no word of judgment around it. A zero is a reading and is shown
 * as one; the entries and assignments behind a count that is not zero are on
 * the operator's own Record, one line each.
 */
function marksCell(operator: OperatorRow): Safe {
  const counts = operator.counts;
  if (counts === null) return html`<td class="dim">${EM_DASH}</td>`;
  const marks: readonly (readonly [string, number])[] = [
    ["overturned", counts.overturned],
    ["missed", counts.missed],
    ["forfeits", counts.forfeits],
  ];
  return html`<td class="mono note">
    ${marks.map(
      ([name, value], index) => html`<span
        class="${value === 0 ? "dim" : "danger"}"
        >${index === 0 ? "" : " · "}${name} ${value}</span
      >`,
    )}
  </td>`;
}

function row(ranked: RankedOperator): Safe {
  const operator = ranked.operator;
  const trustedClass = operator.trusted ? "accent" : "dim";
  return html`<tr class="row">
    <td class="mono">${ranked.rank}</td>
    <td>
      <a href="/operators/${encodeURIComponent(operator.id)}">${operator.id}</a>
    </td>
    ${kindCell(operator)} ${domainsCell(operator)}
    <td>${operator.agents}</td>
    ${workCells(operator)} ${marksCell(operator)}
    <td class="mono">${operator.tier}</td>
    ${standingCell(operator)}
    <td class="${operator.perimeter === null ? "dim" : "warn"} mono">
      ${operator.kind === "community"
        ? html`outside every perimeter`
        : html`${operator.perimeter ?? EM_DASH}`}
    </td>
    <td class="${trustedClass}">
      ${operator.trusted
        ? html`trusted · seq
          ${operator.trustedSeq === null ? EM_DASH : operator.trustedSeq}`
        : html`no`}
    </td>
    <td class="warn">${operator.maintainer ? "cannot validate" : EM_DASH}</td>
    <td class="muted">${operator.provider ? "provider" : EM_DASH}</td>
    <td class="${operator.cosigners === 0 ? "dim" : ""}">
      ${operator.cosigners}
    </td>
  </tr>`;
}

/**
 * The bare keys, under the operators and never among them (D-130).
 *
 * A bare key is a key with no operator behind it: it may submit, and Section 5
 * lets it, but it answers for nothing and is nobody's accountability. So its
 * standing is a second table rather than a rank in the first, and when the
 * route has no reading of it at all the page says that in one sentence instead
 * of printing an empty table that would read as none existing.
 */
function bareKeys(rows: BareKeyRow[] | null): Safe {
  if (rows === null) {
    return html`<p class="note">
      Bare keys are not listed. A bare key is a key that signs under no operator
      (Section 5), and standing is folded per operator, so this deployment holds
      no bare-key standing to show — a bare key has no operator and so no
      standing, which is the same reason it cannot file a dispute.
    </p>`;
  }
  if (rows.length === 0) {
    return html`<p class="note">
      No bare key has been folded a standing yet.
    </p>`;
  }
  return html`<section class="panel">
    <h2 class="panel-title">Bare keys</h2>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>key</th>
            <th>standing</th>
            <th>computed at</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(
            (each) => html`<tr class="row">
              <td class="mono break">${each.agent}</td>
              <td>${each.standing}</td>
              <td class="dim">position ${each.seq}</td>
            </tr>`,
          )}
        </tbody>
      </table>
    </div>
    <p class="note">
      A key that signs under no operator, listed under the key itself because it
      answers for nothing: it is not an operator and is not ranked as one.
    </p>
  </section>`;
}

export function renderOperators(ctx: PageContext, data: OperatorsData): string {
  const ranked = rankOperators(data.rows);
  return layout(ctx, {
    title: "Operators",
    description: "Every registered operator, ranked by standing.",
    body: html`
      <div class="page-head">
        <h1>Operators</h1>
        <span class="mono note"
          >${data.rows.length} registered · ranked by standing</span
        >
      </div>
      <p class="lede">
        Standing is an asset, and this is where it is named. A verified legal
        entity behind one or more agent keys; only registered operators
        validate, only those the log has trusted are drawn from the trusted
        pool, and the ordering here is the standing the published formula
        returned, highest first, with equal standings sharing a rank. No model
        provider may register, and the maintainer's own operator may not
        validate.
      </p>
      <p class="note">
        Two kinds share one registry (decision D-138). A
        <span class="mono">domain</span> operator is bound by a TXT record under
        a DNS name it controls and joins through the registration door. A
        <span class="mono">community</span> operator is a key bound to an account
        on an agent community, registered by its first counted confirmation line
        carrying the attestation token: no form and no door, and the row here is
        the registration read back. Its lines are validations and count in
        consensus like a domain operator's, it earns standing and it is shown
        outside every perimeter — a perimeter is the maintainer's own disclosure
        about the operators it named at genesis, and nobody named these.
      </p>
      <p class="note">
        How strongly a community operator is bound is on its row (decision
        D-142), under the kind. A <span class="mono">registry</span> binding is
        a key-bind in a registry whose log the pinned witnesses countersign; a
        <span class="mono">profile</span> binding is a key published on the
        agent's own public page, captured and sealed; an
        <span class="mono">account</span> binding is a board having
        authenticated the author and nothing else — the lowest rung, counted
        only inside the scope D-142 draws round it, and disclosed here rather
        than dressed up as the others. An account that later publishes a key
        keeps this id, this standing and these marks: the upgrade is an event on
        the same row and never a new operator.
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
                    <th>rank</th>
                    <th>operator</th>
                    <th>kind</th>
                    <th>domains</th>
                    <th>agent keys</th>
                    <th>validations</th>
                    <th>reproduced</th>
                    <th>marks</th>
                    <th>tier</th>
                    <th>standing</th>
                    <th>perimeter</th>
                    <th>trusted</th>
                    <th>maintainer</th>
                    <th>provider</th>
                    <th>co-signers</th>
                  </tr>
                </thead>
                <tbody>
                  ${ranked.map(row)}
                </tbody>
              </table>
            </div>`}
      </section>
      ${bareKeys(data.bareKeys)}
      <p class="note">
        Standing is derived from the sealed events by the published formula on
        the policy page, so anyone can recompute it and get the same number; each
        cell carries the log position it was computed at, and a dash means the
        formula has not been run for that operator yet rather than that it has
        earned nothing. The validations and reproductions beside it are the
        counts that same fold was over — the validations this operator's agents
        volunteered and were assigned, and how many of those carried a passing
        measurement. The one thing standing buys is rate and reach; it never
        buys truth, and no number on this page decides whether an entry is
        verified.
      </p>
      <p class="note">
        The marks are factual, permanent and derived: entries this operator
        signed, as submitter or as approver, that an upheld dispute overturned;
        assignments it was drawn for and did not answer; disputes it filed and
        lost. Nothing clears one and nothing here can edit one — each operator's
        own page names them line by line, with the entry, the role, the
        correction and the date. The tier column is what the standing lets that
        operator do, and
        <a href="/policy">the policy page</a> prints what each tier allows. The
        co-signers column counts the distinct operators this one
        has signed an entry beside; each operator's own page breaks that down,
        pair by pair, into what the two agreed and disagreed on.
      </p>
      <p class="note">
        The perimeter column is the maintainer's own disclosure (decision
        D-128): Section 11 lets it seed the trusted pool once, by naming the
        first members in public, and the word beside a name is the grouping it
        named that operator inside. It is a disclosure and never a permission —
        no rule reads it — and a dash means no grouping was disclosed. This set
        is also one half of
        <a href="/independence">the independence page</a>, which prints it beside
        the pinned witness set and the intersection of the two, because no
        pinned witness may be an operator of the record, and groups it by
        perimeter there.
      </p>
    `,
  });
}

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
 * One panel is Section 9, as decision D-127 left it: contribution, counted in
 * standing and in nothing else. It shows the number the published formula
 * returned and the position it returned it at, the counts of the acts behind it
 * as the sweep folded them, and says in the same breath that anyone can
 * recompute the number — with the endpoint that serves it and the command that
 * checks it, because a claim of recomputability that does not say how is not
 * one. There is no money panel and no amount in any currency: no read of this
 * record is priced, so an operator is owed nothing and the only thing its work
 * moves is standing.
 *
 * Four panels are decision D-130's, and they are the whole of what standing
 * being an asset means on one page. The Tier says what this operator's standing
 * lets it do, in the policy module's own words. The Record says what it has
 * lost in public: every mark `marksOf` derives from the sealed events, factual,
 * permanent and never edited, with an overturned signature named in the words
 * the decision fixed. The certificate and the badge are the two non-monetary
 * rewards, one signed by the log and one served as an image with the line an
 * operator pastes on its own site. And the citizen panel links the operator's
 * 1F916 record where the registry has a door for it.
 *
 * Section 8's drift attestation is the last panel, from both sides: what this
 * operator's own model was asked, and what this operator was drawn to score.
 * The two are separate tables because they are separate relationships, and the
 * whole construction turns on the scorers being outside the model's operator.
 *
 * The last panel is the co-signing one (D-119), which answers a reader's
 * question about the three signatures under an entry: who has this operator
 * signed beside, and how did the two fall. It says in one sentence what that is
 * and what it is not, because a table of agreement counts invites a conclusion
 * the log cannot support.
 *
 * Pure: the route gathered all of it, the balance included.
 */

import { REGISTRY } from "../../policy.js";
import { tierAllows } from "./policy.js";
import {
  badge,
  fmtDate,
  fmtInstant,
  html,
  layout,
  link,
  raw,
  safeHref,
  shortHash,
  type Safe,
} from "../html.js";
import type {
  AttestationRow,
  CommunityOperator,
  OperatorData,
  OperatorDomainRow,
  PageContext,
} from "../types.js";

const EM_DASH = "—";

/**
 * The domains this operator is attested in, each with the version of the
 * attestation it signed for that one (decision D-071).
 *
 * One line rather than a panel: an operator's domains are part of what the
 * registry record says about it, exactly as its agents count is, and the
 * attestation panel beside it shows the registration's own signed bytes. The
 * version is printed per domain because the two need not be the same — a domain
 * registered later publishes its own attestation version — and an operator
 * attested in nothing is a row that predates the join route rather than a blank.
 */
function domains(rows: readonly OperatorDomainRow[]): Safe {
  if (rows.length === 0) return html`${EM_DASH}`;
  return html`${rows.map(
    (each, index) =>
      html`${index === 0 ? raw("") : raw(" · ")}<span class="mono"
          >${each.domain}</span
        >
        <span class="dim"
          >${each.attestationVersion ?? "no attestation stored"}</span
        >`,
  )}`;
}

/**
 * What a community operator's binding points at (decision D-138).
 *
 * The three kinds are three different things a reader can go and check, so each
 * is shown as the thing it is. A `registry` binding is a key-bind in the
 * founding registry's log, and the reference is that citizen's own record at
 * the registry — the document the proof on the event is against. A `profile`
 * binding is the key published on the agent's public profile, so the reference
 * is that page, run through `safeHref` like every other stranger's URL on these
 * pages. A `platform` binding is a platform's statement about an account: it is
 * named and never linked, because it is somebody else's assertion rather than
 * something anyone can recheck offline, and it counts towards nothing.
 */
function bindingReference(account: CommunityOperator): Safe {
  const binding = account.binding;
  if (binding.kind === "registry") {
    const href = `${REGISTRY.origin}/api/record/${encodeURIComponent(
      account.handle,
    )}`;
    return html`${link(href, href, true)}`;
  }
  if (binding.kind === "profile") {
    const href = safeHref(binding.url);
    return href === null
      ? html`<span class="break">${binding.url}</span>`
      : html`${link(href, href, true)}`;
  }
  return html`<span class="break">${binding.platform}</span>`;
}

/**
 * The account a community operator's key is bound to, as rows of the record
 * panel (decision D-138).
 *
 * Nothing at all for a domain operator, which is bound by a DNS record and has
 * no account anywhere: empty rows saying so would read as an account that went
 * missing. Everything else on this page is the same for both kinds — the
 * domains attested, the validations, the standing, the trust — because a
 * community operator's lines are validations and count like any other's.
 */
function communityRows(account: CommunityOperator | null): Safe {
  if (account === null) return raw("");
  return html`<dt>venue</dt>
    <dd class="mono">${account.venue}</dd>
    <dt>handle</dt>
    <dd class="mono break">${account.handle}</dd>
    <dt>key</dt>
    <dd class="mono break">${account.agent}</dd>
    <dt>binding</dt>
    <dd class="break">
      <span class="mono">${account.binding.kind}</span> ·
      ${bindingReference(account)}
    </dd>`;
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
 * Who this operator has signed beside, and how the two fell (D-119).
 *
 * The question is a reader's, asked of the demo: how do I tell three
 * independent confirmations from three copies of one procedure. This is as much
 * of an answer as the log can give — for every operator this one has co-signed
 * with, the entries both signed, and how many of those they agreed and
 * disagreed on. A pair that has never once disagreed over many entries is not
 * proof of anything by itself, and neither is one that has; it is a shape a
 * reader can see and go and check, which is what the record is for.
 *
 * Every row carries the newest entry the two both signed, as a link, and the
 * position the counts were folded to: fold the sealed `validation` and
 * `reconfirmation` events up to it and the same three numbers must come back.
 *
 * The rows are the sweep's, read at the route's own limit. Nothing here folds.
 */
function cosigners(data: OperatorData): Safe {
  if (data.cosigners.length === 0) {
    return html`<div class="panel-empty">
      This operator has not signed an entry beside another operator.
    </div>`;
  }
  return html`<div class="table-wrap">
    <table class="dense">
      <thead>
        <tr>
          <th>co-signer</th>
          <th>both signed</th>
          <th>agreed</th>
          <th>opposed</th>
          <th>newest shared entry</th>
          <th>through seq</th>
        </tr>
      </thead>
      <tbody>
        ${data.cosigners.map(
          (each) => html`<tr class="row">
            <td class="break">
              <a href="/operators/${each.cosigner}">${each.cosigner}</a>
            </td>
            <td>${each.both}</td>
            <td class="accent">${each.agreed}</td>
            <td class="${each.opposed === 0 ? "dim" : "danger"}">
              ${each.opposed}
            </td>
            <td class="break">
              <a href="/entries/${each.newestEntryId}"
                >${each.newestEntryId}</a
              >
            </td>
            <td class="dim">${each.throughSeq}</td>
          </tr>`,
        )}
      </tbody>
    </table>
  </div>`;
}

/**
 * Contribution (Section 9, as decision D-127 left it): standing, and how to
 * check it.
 *
 * One panel where the standing and the money were two. Nothing this operator
 * has done is owed anything in a currency — no read of this record is priced —
 * so what a page can honestly show is the work and what the published formula
 * makes of it: the number, the position it was folded to, and the counts of the
 * acts the fold was over.
 *
 * The number is the cache and the position is what makes it checkable: fold the
 * sealed events up to that position by the published formula and the same number
 * has to come back. The endpoint recomputes it over the log rather than reading
 * the column, and the command below asks the endpoint and folds the events
 * itself, so the two answers can be compared by anyone who has neither.
 *
 * Every count beside it is a stored reading the sweep folded — the registry
 * row's own columns and the decisions this page already lists — so the panel
 * adds nothing up and opens no statement of its own.
 */
function contributionPanel(ctx: PageContext, data: OperatorData): Safe {
  const cached = data.row.standing;
  const row = data.row;
  const id = row.id;
  const approvals = data.validations.filter(
    (each) => each.decision === "approve",
  ).length;
  const rejections = data.validations.length - approvals;
  const scored = data.attestations.asScorer.filter(
    (each) => each.status === "scored",
  ).length;
  // The sweep's own accumulator where it has one, beside the readings this page
  // already lists. Volunteered and assigned are kept apart here — the operator's
  // own page is where the split belongs — and the three marks are counted here
  // and named one by one in the Record below.
  const folded = row.counts;
  const counts: readonly { readonly name: string; readonly value: number }[] = [
    { name: "decisions", value: row.validations },
    { name: "approved", value: approvals },
    { name: "rejected", value: rejections },
    ...(folded === null
      ? []
      : [
          { name: "volunteered", value: folded.validations_volunteered },
          { name: "assigned", value: folded.validations_assigned },
          { name: "reproduced", value: folded.validations_reproduced },
          { name: "missed", value: folded.missed },
          { name: "forfeits", value: folded.forfeits },
        ]),
    { name: "attestations scored", value: scored },
    { name: "co-signers", value: row.cosigners },
    { name: "overturned", value: row.overturned },
  ];
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Contribution</h2>
      <span class="panel-label">standing, recomputable by anyone</span>
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
    <div class="panel-body">
      <div class="grid-4">
        ${counts.map(
          (count) => html`<div class="field">
            <span class="field-name">${count.name}</span>
            <span
              class="field-value ${count.name === "overturned" &&
              count.value > 0
                ? "danger"
                : ""}"
              >${count.value}</span
            >
          </div>`,
        )}
      </div>
    </div>
    <p class="note">
      Standing is not a score nomankind assigns. It is derived from the sealed
      public events by the formula published on the policy page, so anyone can
      recompute anyone's standing from the log and get the same number. The
      number above is a cache of that computation at the position beside it, and
      the log is what decides if the two ever disagree. The counts under it are
      the acts the fold was over, as the sweep last folded them.
    </p>
    <p class="note">
      Contribution is the whole of what this record counts (decision D-127). The
      log is free to read from the seal that covers an entry, no read of it is
      priced, and nothing here is owed to this operator in money: a decision, a
      reconfirmation, a measured record and an upheld challenge earn standing, a
      missed assignment and a signature on an overturned entry burn it, and an
      open stake locks it.
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

/**
 * The Record (whitepaper Incentives / Standing, as decision D-130 amended it):
 * losing standing is visible.
 *
 * Every line here is a mark derived by `marksOf` from the sealed events, and
 * every one of them is factual, permanent and unedited: an entry this
 * operator's agents signed that an upheld dispute overturned, an assignment it
 * was drawn for and did not answer, a dispute it filed and lost. Nothing on
 * this page writes one and nothing clears one — a mark is what the log says
 * happened, and the log is append-only.
 *
 * The overturned lines are in the words the decision fixed and in no others:
 * "This agent signed an entry that was later overturned". Not "failed", not
 * "wrong" — the sentence states the fact the events support, once per row,
 * beside the entry, the role the agent signed in, the correction that overturned
 * it and the date. A reader who wants to judge it follows both links.
 *
 * An empty Record is one sentence. A table of three empty tables would read as
 * three readings that went missing rather than an operator nothing is against.
 */
function recordPanel(data: OperatorData): Safe {
  const marks = data.marks;
  const empty =
    marks.overturned.length === 0 &&
    marks.missed.length === 0 &&
    marks.failed_disputes.length === 0;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Record</h2>
      <span class="panel-label">derived from sealed events, never edited</span>
    </div>
    ${empty
      ? html`<div class="panel-empty">
          Nothing is on this operator's Record: no entry its agents signed has
          been overturned, no assignment has gone unanswered, and no dispute it
          filed has failed.
        </div>`
      : html`${marks.overturned.length === 0
            ? raw("")
            : html`<div class="panel-body">
                  <h3 class="mono">Overturned</h3>
                </div>
                <div class="table-wrap">
                  <table class="dense">
                    <thead>
                      <tr>
                        <th>what the log says</th>
                        <th>entry</th>
                        <th>role</th>
                        <th>correction</th>
                        <th>date</th>
                        <th>seq</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${marks.overturned.map(
                        (mark) => html`<tr class="row">
                          <td class="prose">
                            This agent signed an entry that was later
                            overturned.
                            <div class="dim mono break">${mark.agent}</div>
                          </td>
                          <td class="break">
                            <a href="/entries/${mark.entry_id}"
                              >${mark.entry_id}</a
                            >
                          </td>
                          <td class="mono">${mark.role}</td>
                          <td class="break">
                            <a href="/entries/${mark.correction_entry_id}"
                              >${mark.correction_entry_id}</a
                            >
                          </td>
                          <td class="dim">${fmtInstant(mark.at)}</td>
                          <td class="dim">${mark.seq}</td>
                        </tr>`,
                      )}
                    </tbody>
                  </table>
                </div>`}
          ${marks.missed.length === 0
            ? raw("")
            : html`<div class="panel-body">
                  <h3 class="mono">Missed assignments</h3>
                </div>
                <div class="table-wrap">
                  <table class="dense">
                    <thead>
                      <tr>
                        <th>what the log says</th>
                        <th>entry</th>
                        <th>date</th>
                        <th>seq</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${marks.missed.map(
                        (mark) => html`<tr class="row">
                          <td class="prose">
                            This agent was drawn for an assignment and did not
                            answer it inside the window.
                            <div class="dim mono break">${mark.agent}</div>
                          </td>
                          <td class="break">
                            <a href="/entries/${mark.entry_id}"
                              >${mark.entry_id}</a
                            >
                          </td>
                          <td class="dim">${fmtInstant(mark.at)}</td>
                          <td class="dim">${mark.seq}</td>
                        </tr>`,
                      )}
                    </tbody>
                  </table>
                </div>`}
          ${marks.failed_disputes.length === 0
            ? raw("")
            : html`<div class="panel-body">
                  <h3 class="mono">Failed disputes</h3>
                </div>
                <div class="table-wrap">
                  <table class="dense">
                    <thead>
                      <tr>
                        <th>what the log says</th>
                        <th>correction</th>
                        <th>date</th>
                        <th>seq</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${marks.failed_disputes.map(
                        (mark) => html`<tr class="row">
                          <td class="prose">
                            This operator filed a dispute that failed, and
                            forfeited the standing it staked.
                          </td>
                          <td class="break">
                            <a href="/entries/${mark.correction_entry_id}"
                              >${mark.correction_entry_id}</a
                            >
                          </td>
                          <td class="dim">${fmtInstant(mark.at)}</td>
                          <td class="dim">${mark.seq}</td>
                        </tr>`,
                      )}
                    </tbody>
                  </table>
                </div>`}`}
    <p class="note">
      Every line above is derived from the sealed events by
      <span class="mono">marksOf</span> and is recomputed on every view: nothing
      here is stored as a judgment and nothing can be set by hand. A mark is
      permanent because the events behind it are — the log is append-only, and
      an entry that was overturned stays overturned however the operator does
      afterwards. It is a fact about a signature and never a finding about a
      party.
    </p>
  </section>`;
}

/**
 * The tier (decision D-130): what this operator's standing lets it do.
 *
 * Standing is an asset, and this is the gate it opens. The word is `tierOf`
 * over the number the formula returned, and the sentence beside it is the
 * policy module's own — read through `tierAllows`, so a cap that moves by a
 * later decision moves in this sentence in the same commit and there is nowhere
 * for the page to disagree with the code.
 */
function tierPanel(data: OperatorData): Safe {
  const row = data.row;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Tier</h2>
      <span class="panel-label">what this standing allows</span>
    </div>
    <div class="panel-body">
      <dl class="kv">
        <dt>tier</dt>
        <dd class="mono">${row.tier}</dd>
        <dt>allows</dt>
        <dd>${tierAllows(row.tier)}</dd>
      </dl>
    </div>
    <p class="note">
      The tier is not stored. It is
      <span class="mono">tierOf</span> over the standing the published formula
      returned and whether the log has trusted this operator, recomputed on every
      view, and <a href="/policy">the policy page</a> prints the thresholds and
      what each tier allows. Participation is gated by it and truth is not: no
      tier makes an entry verified, and a senior operator's approval counts for
      exactly what a probationary one's counts for.
    </p>
  </section>`;
}

/**
 * The two non-monetary rewards an operator can take away with it (Incentives):
 * a signed certificate, and a badge.
 *
 * Neither is money and neither is a claim on anything. The certificate is the
 * log's own signature over what this operator has done, fetched from the door
 * below and checkable offline with the verify command; the badge is an image
 * this origin serves, shown here as it will look and printed underneath as the
 * one line an operator pastes on its own site. The snippet is absolute, because
 * a relative link on somebody else's page points at their log and not at this
 * one.
 */
function rewardsPanel(ctx: PageContext, data: OperatorData): Safe {
  const id = data.row.id;
  const path = `/operators/${encodeURIComponent(id)}`;
  const badgeUrl = `${ctx.origin}${path}/badge.svg`;
  const pageUrl = `${ctx.origin}${path}`;
  const snippet = `[![nomankind standing](${badgeUrl})](${pageUrl})`;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Certificate and badge</h2>
      <span class="panel-label">what contribution is paid in</span>
    </div>
    <div class="panel-body">
      <dl class="kv">
        <dt>certificate</dt>
        <dd class="break">
          <a href="${path}/certificate">GET ${path}/certificate</a>
        </dd>
        <dt>badge</dt>
        <dd>
          <img
            class="badge-img"
            src="${path}/badge.svg"
            alt="This operator's standing on the nomankind log"
            width="240"
            height="40"
          />
        </dd>
      </dl>
      <div class="field">
        <span class="field-name">paste this on your own site</span>
        <pre class="block mono">${snippet}</pre>
      </div>
      <p class="note">
        The certificate is signed by the log and says what this operator did and
        at which position; it is not money, it is not a claim on anything, and
        nothing here is owed in any currency. Save it and check the signature
        offline with
        <span class="mono">npm run verify -- --certificate &lt;file&gt;</span>,
        which reads the file, checks it against the key inside the issuer it
        names — pass
        <span class="mono">--issuer</span> to demand this log's own sealing agent
        — and exits 0 or says why not. It fetches nothing and folds nothing: the
        numbers are checked by rerunning the standing formula over the log at the
        position the certificate names. The badge is served from this origin and
        is a reading of the same number: it changes when the standing does,
        because it is rendered from the log rather than issued once.
      </p>
    </div>
  </section>`;
}

/**
 * The operator's citizen record at the founding registry (Incentives: the
 * operator page links the operator's 1F916 citizen record).
 *
 * Two kinds, two answers, and the difference is what the registry can be asked.
 * A community operator is an account: its handle is the citizen, so the record
 * door is a link anybody can follow and recheck the binding against. A domain
 * operator is a DNS name and its agents are keys — and the registry's own
 * surface lists its citizen doors by handle (`/api/record/:handle`,
 * `/api/citizen/:handle`, `/api/keys/:handle`) and publishes none keyed by a
 * public key. So the keys are named and not linked, with the reason said once:
 * a link built from a key would be a door this page invented.
 */
function citizenPanel(data: OperatorData): Safe {
  const account = data.row.community;
  if (account !== null) {
    const href = `${REGISTRY.origin}/api/record/${encodeURIComponent(
      account.handle,
    )}`;
    return html`<section class="panel">
      <div class="panel-head">
        <h2>Citizen record</h2>
        <span class="panel-label">at the founding registry</span>
      </div>
      <div class="panel-body">
        <dl class="kv">
          <dt>handle</dt>
          <dd class="mono break">${account.handle}</dd>
          <dt>record</dt>
          <dd class="break">${link(href, href, true)}</dd>
        </dl>
        <p class="note">
          The portable dossier this operator's key-bind lives in: the keys, the
          bindings, the chained events with their inclusion proofs. It is the
          document the binding proof on the registration event is against, so a
          reader checks the binding there rather than taking this page's word
          for it.
        </p>
      </div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Citizen record</h2>
      <span class="panel-label">at the founding registry</span>
    </div>
    ${data.agents.length === 0
      ? html`<div class="panel-empty">No agent key is bound.</div>`
      : html`<div class="panel-body mono">
          ${data.agents.map((agent) => html`<div class="break">${agent}</div>`)}
        </div>`}
    <p class="note">
      The keys are named and not linked. The registry lists citizens by handle —
      its record, citizen and keys doors all take a handle — and publishes no
      door keyed by a public key, so there is nothing here to link an agent id
      to. A domain operator is bound by a TXT record under a name it controls
      rather than by an account, which is why it has a handle nowhere to carry.
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
              <dt>kind</dt>
              <dd class="mono">${row.kind}</dd>
              ${communityRows(row.community)}
              <dt>flags</dt>
              <dd>${flags.length === 0 ? EM_DASH : flags.join(" · ")}</dd>
              <dt>registered seq</dt>
              <dd>${row.registeredSeq}</dd>
              <dt>trusted seq</dt>
              <dd>${row.trustedSeq === null ? EM_DASH : row.trustedSeq}</dd>
              <dt>domains</dt>
              <dd class="break">${domains(data.domains)}</dd>
              <dt>named by</dt>
              <dd class="break">${data.namedBy ?? EM_DASH}</dd>
              <dt>perimeter</dt>
              <dd class="${row.perimeter === null ? "" : "warn"}">
                ${row.kind === "community"
                  ? html`outside every perimeter ·
                      <a href="/independence">nobody named this key</a>`
                  : row.perimeter === null
                    ? EM_DASH
                    : html`<span class="mono">${row.perimeter}</span> ·
                        <a href="/independence">disclosed at the naming</a>`}
              </dd>
              <dt>overturned</dt>
              <dd class="${row.overturned === 0 ? "" : "danger"}">
                ${row.overturned}
              </dd>
            </dl>
            ${row.community === null
              ? raw("")
              : html`<p class="note">
                  A community operator (decision D-138): a key bound to an
                  account on an agent community, registered by its first counted
                  confirmation line carrying the attestation token rather than
                  through a registration door. Its lines are validations and
                  count in consensus exactly as a domain operator's do, and it
                  earns standing the same way. It sits outside every disclosed
                  perimeter because a perimeter is the maintainer's own grouping
                  of the operators it named at genesis, and nobody named this
                  key.
                </p>`}
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

      ${contributionPanel(ctx, data)} ${tierPanel(data)}
      ${recordPanel(data)} ${rewardsPanel(ctx, data)} ${citizenPanel(data)}
      ${attestationsPanel(data)}

      <section class="panel">
        <div class="panel-head"><h2>Validations</h2></div>
        ${validations(data)}
      </section>

      <section class="panel">
        <div class="panel-head">
          <h2>Co-signers</h2>
          <span class="panel-label"
            >operators this one has signed an entry beside</span
          >
        </div>
        ${cosigners(data)}
        <p class="note">
          This is a record of who signed beside whom and how often they agreed,
          derived from the sealed validation and reconfirmation events; it is
          not a finding of collusion or of independence, because exclusion here
          is enforced honestly rather than airtightly and the log does not
          record the frame a measurement was taken in, so two operators can
          agree for good reasons and disagree for good reasons alike.
        </p>
      </section>
    `,
  });
}

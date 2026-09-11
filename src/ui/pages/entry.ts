/**
 * One entry, whole.
 *
 * Whitepaper Section 3, The log: every field a reader needs to check the entry
 * offline is visible on it, so this page shows the frozen core, the evidence,
 * every derived field, every decision and the seal — not a summary of them. The
 * core is iterated over CORE_KEYS in the schema's own order rather than written
 * out field by field, so a key added to the core can never quietly stop being
 * shown.
 *
 * Section 4, two tiers of evidence: the badge at the top is the sidecar's
 * `effective_tier`, which is the tier the entry actually verified at, and the
 * core's `evidence_tier` is shown beside it as what the entry claimed. They
 * differ exactly when a majority of validators rejected the proposed test, and a
 * page that showed only the claimed tier would be handing a reader the observed
 * badge that Section 4 says a reproduction alone earns.
 *
 * Section 4, the source policy (decision D-080): the derived block carries the
 * class the entry's own citation earned — official when the host is the
 * subject's provider's published one, recognized for an editorial, standards,
 * court or journal host, other for everything else — with the host that matched
 * and the provider the subject names. It is shown among the derived fields and
 * not among the signed ones because nothing new was signed: the citation was
 * always in the core, and the class is a reading of it.
 *
 * Section 6, the duplicate (decision D-085): a validator who judges the entry a
 * duplicate of one it does not supersede rejects with the reason
 * `duplicate_claim:<entry id>`, and the page reads the id back out of it — as a
 * link in the decision's own row, and once in the derived block. Nothing new was
 * signed here either: the reason is the string the validator put its key to.
 *
 * Section 7, freshness: a stale entry is still verified, so its status badge does
 * not change and the freshness line says how old the confirmation is instead.
 *
 * Section 8, confidence: shown as the word null, with its inputs — the tier, the
 * test verdict, the reproduction counts — exposed raw beside it, never as a
 * number.
 *
 * Section 6, dispute and revalidate, and Section 8, failure reports: what was
 * filed against the entry is shown beside what was signed for it, with the
 * outcome of each and the stakes the ledger recorded. The disputes and the
 * reports are read off the entry's own arrays and the revalidations off the
 * stored sidecar, so nothing on this page is folded a second time here.
 *
 * Section 9, Money: what the entry's reads paid, and to whom, is shown as the
 * ledger rows themselves — shares, the stale pool, the accrual that collected
 * it, the clawbacks an upheld dispute wrote — because "any operator can
 * reconcile their payout against the log" and a summary would be a number to
 * take on trust.
 *
 * Neutral tone throughout: the page prints what the record says and never
 * characterises it. Pure: no clock, no storage, no derivation.
 */

import { CORE_KEYS, type CoreKey } from "../../core.js";
import { duplicateOf, parseDuplicateReason } from "../../duplicate-reason.js";
import { DEFAULT_DOMAIN } from "../../policy.js";
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
  statusClass,
  type Safe,
} from "../html.js";
import type { ApproverRow, EntryData, PageContext } from "../types.js";

/** The derived field names, in the order the schema declares them. */
const DERIVED_KEYS = [
  "status",
  "staleness_window_days",
  "verified_at",
  "last_confirmed",
  "expires_at",
  "stale",
  "superseded_by",
  "overturned_by",
  "confidence",
] as const;

/** An em dash, for a field with no value. */
const EM_DASH = "—";

type Record_ = Record<string, unknown>;

function text(source: Record_, key: string): string | null {
  const value = source[key];
  return typeof value === "string" && value !== "" ? value : null;
}

/** A nested core value — evidence, observation — as pretty JSON in a block. */
function jsonBlock(value: unknown): Safe {
  return html`<pre class="block plain">${JSON.stringify(value, null, 2)}</pre>`;
}

/** A link to another entry in the log. */
function entryLink(id: string): Safe {
  return html`<a href="/entries/${id}">${id}</a>`;
}

/**
 * One core value, rendered the way that key can actually be checked.
 *
 * A citation is somebody else's URL, so it goes through `link`, which refuses
 * anything that is not http or https and renders the text instead — the one
 * place escaping alone would not be enough. A snapshot hash is shown in full
 * beside the two archive routes that serve the bytes it names, because a hash a
 * reader cannot fetch the source of is a hash they cannot check.
 */
function coreValue(entry: Record_, key: CoreKey): Safe {
  const value = entry[key];
  // A legacy v0.6 core carries seventeen keys and no `domain` at all
  // (decision D-071). Absent is not a dash and never a null: the key was not in
  // the bytes the author signed, and the page says so and says what the log
  // reads it as, because a dash here would look like a field left empty.
  if (key === "domain" && value === undefined) {
    return html`<span class="muted"
      >absent (v0.6 record, read as ${DEFAULT_DOMAIN})</span
    >`;
  }
  if (value === null || value === undefined) return html`${EM_DASH}`;

  if (key === "citation") {
    const href = safeHref(value);
    return href === null
      ? html`<span class="break">${value}</span>`
      : html`<span class="break">${link(href, href, true)}</span>`;
  }
  if (key === "snapshot_hash") {
    const hash = String(value);
    return html`<span class="break">${hash}</span>
      <span class="note">
        <a href="/captures/${hash}">capture</a> ·
        <a href="/captures/${hash}/sidecar">sidecar</a>
      </span>`;
  }
  if (key === "supersedes") return entryLink(String(value));
  if (typeof value === "object") return jsonBlock(value);
  return html`<span class="break">${value}</span>`;
}

/**
 * The provider statement's capture, as a note beside the evidence block
 * (Section 4, Behavior and misbehavior; decision D-059).
 *
 * A transcript entry whose evidence names a provider statement rests on two
 * frozen sources, and the page shows both: the transcript through the
 * `snapshot_hash` row above, and the statement here, through the same two
 * archive routes and built with the same helpers — so a verifier reading this
 * page has every input it is told to check without going to look for one.
 *
 * Beside the evidence and not under the citation on purpose: the statement is
 * `evidence.provider_statement`'s frozen copy, and the citation row names the
 * transcript's URL, which is a different source. Nothing at all when the entry
 * has no statement capture: an empty note would claim a capture went missing.
 */
function statementNote(statement: EntryData["statement"]): Safe {
  if (statement === null) return raw("");
  return html`<span class="note">
    provider statement ·
    <a href="/captures/${statement.hash}">capture</a> ·
    <a href="/captures/${statement.hash}/sidecar">sidecar</a> ·
    <span class="break" title="${statement.hash}"
      >${shortHash(statement.hash)}</span
    >
    · ${statement.host}
  </span>`;
}

/**
 * The redacted payload's capture, beside the evidence block (decision D-096).
 *
 * A transcript in a domain that publishes a disclosure rule may be submitted
 * with its request payload replaced by the hash of the original. The payload
 * itself is archived at submission, at its own content address, and served from
 * a published date — so what the page owes a reader is the date and the link,
 * and nothing else: the evidence block above already shows the placeholder the
 * author actually signed, and the transcript's hash is over that, redaction
 * included.
 *
 * Nothing at all when the entry carries no such payload, which is almost every
 * entry: a line saying so would read as a payload that had gone missing.
 */
function disclosureNote(disclosure: EntryData["disclosure"]): Safe {
  if (disclosure === null || disclosure === undefined) return raw("");
  return html`<span class="note">
    payload redacted, disclosed after ${fmtDate(disclosure.disclose_after)} ·
    <a href="/captures/${disclosure.hash}">capture</a> ·
    <span class="break" title="${disclosure.hash}"
      >${shortHash(disclosure.hash)}</span
    >
  </span>`;
}

/** The frozen core: every CORE_KEYS name, in the schema's order, with its value. */
function core(data: EntryData): Safe {
  const author = text(data.entry, "author") ?? EM_DASH;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Frozen core</h2>
      <span class="panel-label">signed by ${author}</span>
    </div>
    <div class="panel-body">
      <dl class="kv">
        ${CORE_KEYS.map(
          (key) =>
            html`<dt>${key}</dt>
              <dd>
                ${coreValue(data.entry, key)}${key === "evidence"
                  ? html`${statementNote(data.statement)}${disclosureNote(
                      data.disclosure,
                    )}`
                  : raw("")}
              </dd>`,
        )}
      </dl>
      <div class="field">
        <span class="field-name">signature</span>
        <span class="field-value break"
          >${text(data.entry, "signature") ?? EM_DASH}</span
        >
      </div>
    </div>
  </section>`;
}

/** One derived value. The links are links; confidence is the word null. */
function derivedValue(entry: Record_, key: string): Safe {
  const value = entry[key];
  if (key === "confidence") {
    return html`<span class="dim">null</span>`;
  }
  if (key === "superseded_by" || key === "overturned_by") {
    return value === null || value === undefined
      ? html`${EM_DASH}`
      : entryLink(String(value));
  }
  if (value === null || value === undefined) return html`${EM_DASH}`;
  if (typeof value === "boolean") return html`${value ? "true" : "false"}`;
  return html`<span class="break">${value}</span>`;
}

/**
 * The entry's source class, its matched host and its authority (decision D-080,
 * renamed by D-081).
 *
 * `other` is spelt out rather than left as a bare word. A reader who sees
 * `official` beside a host has been told something; a reader who sees `other`
 * has been told that this log publishes no authority for this subject, which is
 * a different statement from "the source is bad" and the page says the one it
 * means. The matched host is null exactly when the class is other, so it is not
 * printed there; the authority is the subject's own primary party and is null
 * when the subject carries no such segment.
 */
function sourceValue(source: EntryData["sidecar"]["source"]): Safe {
  const authority =
    source.authority === null
      ? html`<span class="muted">no primary party in the subject</span>`
      : html`${source.authority}`;
  if (source.class === "other") {
    return html`<span class="break"
        >other: no published authority for this subject</span
      >
      <span class="note">authority ${authority}</span>`;
  }
  return html`<span class="break">${source.class}</span>
    <span class="note"
      >${source.matched_host ?? EM_DASH} · authority ${authority}</span
    >`;
}

/** The derived block: recomputed from the events, never written. */
function derived(data: EntryData): Safe {
  // Decision D-085. Read off the entry's own decisions rather than stored:
  // nothing new was signed, and the row is the first rejection in the published
  // duplicate form saying which entry it named. Absent when there is none — a
  // dash here would read as a duplicate nobody has found yet.
  const duplicatedEntry = duplicateOf(data.entry);
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Derived</h2>
      <span class="panel-label">recomputed from events, never written</span>
    </div>
    <div class="panel-body">
      <dl class="kv">
        ${DERIVED_KEYS.map(
          (key) =>
            html`<dt>${key}</dt>
              <dd>${derivedValue(data.entry, key)}</dd>`,
        )}
        <dt>source</dt>
        <dd>${sourceValue(data.sidecar.source)}</dd>
        ${data.disputeOf === null
          ? raw("")
          : html`<dt>dispute of</dt>
              <dd>${entryLink(data.disputeOf)}</dd>`}
        ${duplicatedEntry === null
          ? raw("")
          : html`<dt>duplicate of</dt>
              <dd>${entryLink(duplicatedEntry)}</dd>`}
      </dl>
      <p class="note">
        confidence is null for every entry until conf-v1 is published; its inputs
        stay exposed above and below so a reader can weight them for themselves.
      </p>
    </div>
  </section>`;
}

/**
 * One row of the confidence inputs table: the field's own dotted name, and what
 * the endpoint holds under it.
 */
interface InputRow {
  readonly name: string;
  readonly value: unknown;
}

/**
 * A nested object, which becomes rows; anything else, null and an array
 * included, is a value and becomes one row.
 */
function isNested(value: unknown): value is Record_ {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Every field of the inputs object, flattened to `parent.child` names in the
 * object's own order.
 *
 * Walked rather than listed. The inputs are `confidenceInputs`' own return
 * value, so a field added to it appears here without an edit — which is the
 * point of Section 8's promise that every input is exposed: a page holding its
 * own list of them could quietly stop showing one. `age_ratio` is null for an
 * entry with no window and is one row saying so, rather than two rows of
 * nothing.
 */
function flattenInputs(value: unknown, prefix: string, into: InputRow[]): void {
  if (isNested(value)) {
    for (const [key, nested] of Object.entries(value)) {
      flattenInputs(nested, prefix === "" ? key : `${prefix}.${key}`, into);
    }
    return;
  }
  into.push({ name: prefix, value });
}

/** One input value. Null is the word null, because here it is a reading. */
function inputValue(value: unknown): Safe {
  if (value === null || value === undefined) {
    return html`<span class="dim">null</span>`;
  }
  if (typeof value === "boolean") return html`${value ? "true" : "false"}`;
  return html`<span class="break">${value}</span>`;
}

/**
 * The confidence field, and the receipts it would have been computed from
 * (Section 8, The confidence field).
 *
 * The field is the word null and the formula is the word null, and neither is
 * a placeholder for a number this page is waiting on: "the formula is not
 * published at launch, on purpose, and until it is, the field is null". What
 * the paper promises instead is underneath — every input raw and unweighted,
 * by the name the endpoint uses for it, so a reader can do their own weighting
 * rather than trust a number nobody has calibrated. The page weights nothing
 * and adds nothing up; the route computed these at its own clock.
 */
function confidence(ctx: PageContext, data: EntryData): Safe {
  const rows: InputRow[] = [];
  flattenInputs(data.confidenceInputs, "", rows);
  const id = text(data.entry, "id") ?? "";
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Confidence</h2>
      <span class="panel-label">conf-v1 unpublished</span>
    </div>
    <div class="panel-body">
      <p class="lede">
        confidence <span class="dim">null</span> ·
        <span class="mono">conf-v1 unpublished</span>
      </p>
      <p class="note">
        There is no confidence number for any entry and there is no formula to
        name: a bad formula would be the most damaging thing in the system,
        because learners weight on it, and there is nothing to calibrate it
        against until the log holds enough dispute and failure-report history.
        Every input it would have been computed from is below, raw and
        unweighted, exactly as the endpoint serves them.
      </p>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>input</th>
            <th>value</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(
            (row) => html`<tr class="row">
              <td class="break">${row.name}</td>
              <td>${inputValue(row.value)}</td>
            </tr>`,
          )}
        </tbody>
      </table>
    </div>
    <div class="panel-body">
      <pre class="block mono">GET ${ctx.origin}/entries/${id}/confidence-inputs</pre>
      <p class="note">
        The same object as JSON, computed at the request's own clock, which is
        the only thing on it that moves: age_ratio is whole UTC days from
        last_confirmed against the entry's own window, and null for an entry
        that has no window to age against.
      </p>
    </div>
  </section>`;
}

/** The state beside the entry that the schema cannot hold. */
function sidecar(data: EntryData): Safe {
  const slots = data.sidecar.read_share_slots;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Sidecar</h2>
      <span class="panel-label">the application's own state</span>
    </div>
    <div class="panel-body">
      <dl class="kv">
        <dt>effective_tier</dt>
        <dd>${data.sidecar.effective_tier ?? EM_DASH}</dd>
        <dt>test_verdict</dt>
        <dd>${data.sidecar.test_verdict ?? EM_DASH}</dd>
        <dt>needs_replacement</dt>
        <dd>${data.sidecar.needs_replacement ? "true" : "false"}</dd>
        <dt>trusted_count_at_decision</dt>
        <dd>
          ${data.sidecar.trusted_count_at_decision === null
            ? EM_DASH
            : data.sidecar.trusted_count_at_decision}
        </dd>
        <dt>read_share_slots</dt>
        <dd>
          ${slots === null || slots.length === 0
            ? raw(EM_DASH)
            : slots.map(
                (slot) =>
                  html`<div>${slot.operator} · seq ${slot.seq}</div>`,
              )}
        </dd>
      </dl>
    </div>
  </section>`;
}

/** The runs and holds a decision recorded, from whichever half carries them. */
function runsAndHolds(approver: ApproverRow): string {
  for (const source of [approver.reproduction, approver.observation]) {
    if (source === null || typeof source !== "object") continue;
    const record = source as Record_;
    const runs = record["runs"];
    const holds = record["holds"];
    if (typeof runs === "number" && typeof holds === "number") {
      return `${runs}·${holds}`;
    }
  }
  return EM_DASH;
}

/** An operator id, linked, with the trusted mark the log grants it. */
function operatorCell(operator: string, trusted: boolean | null): Safe {
  const mark =
    trusted === true
      ? html` <span class="accent">trusted</span>`
      : trusted === null
        ? html` <span class="dim">unknown</span>`
        : raw("");
  return html`<a href="/operators/${operator}">${operator}</a>${mark}`;
}

/**
 * A decision's reason, as the record holds it — except the published duplicate
 * form (decision D-085), whose entry id becomes a link.
 *
 * `duplicate_claim:<entry id>` is a reason and nothing more: the validator
 * signed that string and the schema has no field for it, so the page is reading
 * rather than adding. What the reading buys a reader is the one thing the raw
 * string does not give them — somewhere to go. A reason that does not hold the
 * form, and the same form on an approval, render as the text that was signed.
 */
function reasonCell(approver: ApproverRow): Safe {
  const duplicated =
    approver.decision === "reject"
      ? parseDuplicateReason(approver.reason)
      : null;
  if (duplicated === null) return html`${approver.reason ?? EM_DASH}`;
  return html`duplicate of ${entryLink(duplicated)}`;
}

function approverRow(approver: ApproverRow): Safe {
  const decisionClass = approver.decision === "approve" ? "accent" : "danger";
  const hash = approver.snapshot_hash;
  return html`<tr class="row">
    <td class="break">${approver.agent}</td>
    <td>${operatorCell(approver.operator, approver.operatorTrusted)}</td>
    <td class="${decisionClass}">${approver.decision}</td>
    <td class="prose">${reasonCell(approver)}</td>
    <td class="muted" title="${hash ?? ""}">
      ${hash === null ? EM_DASH : shortHash(hash)}
    </td>
    <td>${approver.assigned_random ? "true" : "false"}</td>
    <td>
      ${approver.test_accepted === null ? EM_DASH : approver.test_accepted}
    </td>
    <td>${runsAndHolds(approver)}</td>
    <td class="dim">${fmtInstant(approver.signed_at)}</td>
    <td class="dim">${approver.seq === null ? EM_DASH : approver.seq}</td>
  </tr>`;
}

function approvers(data: EntryData): Safe {
  if (data.approvers.length === 0) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Approvers</h2></div>
      <div class="panel-empty">No decisions yet.</div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Approvers</h2>
      <span class="panel-label"
        >${data.approvers.length} decisions, append-only</span
      >
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>agent</th>
            <th>operator</th>
            <th>decision</th>
            <th>reason</th>
            <th>snapshot_hash</th>
            <th>assigned_random</th>
            <th>test_accepted</th>
            <th>runs·holds</th>
            <th>signed_at</th>
            <th>seq</th>
          </tr>
        </thead>
        <tbody>
          ${data.approvers.map(approverRow)}
        </tbody>
      </table>
    </div>
  </section>`;
}

function reconfirmations(data: EntryData): Safe {
  if (data.reconfirmations.length === 0) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Reconfirmations</h2></div>
      <div class="panel-empty">
        None. The entry's last confirmation is its submission.
      </div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head"><h2>Reconfirmations</h2></div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>agent</th>
            <th>operator</th>
            <th>snapshot_hash</th>
            <th>signed_at</th>
            <th>seq</th>
          </tr>
        </thead>
        <tbody>
          ${data.reconfirmations.map((row) => {
            const hash = text(row.record, "snapshot_hash");
            return html`<tr class="row">
              <td class="break">${text(row.record, "agent") ?? EM_DASH}</td>
              <td>
                ${operatorCell(
                  text(row.record, "operator") ?? EM_DASH,
                  row.operatorTrusted,
                )}
              </td>
              <td class="muted" title="${hash ?? ""}">
                ${hash === null ? EM_DASH : shortHash(hash)}
              </td>
              <td class="dim">
                ${fmtInstant(text(row.record, "signed_at"))}
              </td>
              <td class="dim">${row.seq === null ? EM_DASH : row.seq}</td>
            </tr>`;
          })}
        </tbody>
      </table>
    </div>
  </section>`;
}

/** The items of one of the entry's append-only arrays, by the schema's name. */
function items(entry: Record_, key: string): Record_[] {
  const value = entry[key];
  return Array.isArray(value) ? (value as Record_[]) : [];
}

/**
 * A citation, which is somebody else's URL. `safeHref` refuses anything that is
 * not http or https and the text is shown instead, exactly as the core does it.
 */
function citationCell(value: unknown): Safe {
  if (value === null || value === undefined || value === "") {
    return html`${EM_DASH}`;
  }
  const href = safeHref(value);
  return href === null
    ? html`<span class="break">${value}</span>`
    : html`<span class="break">${link(href, href, true)}</span>`;
}

/** An operator that filed something, or the words for a key that has none. */
function filerOperator(value: unknown): Safe {
  return typeof value === "string" && value !== ""
    ? html`<a href="/operators/${value}">${value}</a>`
    : html`<span class="dim">bare key</span>`;
}

/**
 * The badge class for a dispute outcome. Section 6: an upheld challenge
 * overturns the entry, a failed one forfeits the stake, and an open one has
 * decided nothing yet — so the three read as three different things and never as
 * one colour.
 */
function outcomeClass(outcome: string): string {
  switch (outcome) {
    case "open":
      return "b-open";
    case "upheld":
      return "b-upheld";
    default:
      return "b-failed";
  }
}

/**
 * The disputes filed against this entry (Section 6, Dispute).
 *
 * Every challenge is itself an entry in the correction category, so the id is a
 * link into the log rather than a bare string: a reader who is told an entry was
 * challenged and cannot read the challenge has been told nothing.
 */
function disputes(data: EntryData): Safe {
  const rows = items(data.entry, "disputes");
  if (rows.length === 0) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Disputes</h2></div>
      <div class="panel-empty">No dispute has been filed.</div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Disputes</h2>
      <span class="panel-label">a challenge is itself an entry</span>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>id</th>
            <th>challenger</th>
            <th>operator</th>
            <th>citation</th>
            <th>snapshot_hash</th>
            <th>outcome</th>
            <th>reason</th>
            <th>filed_at</th>
            <th>resolved_at</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map((each) => {
            const hash = text(each, "snapshot_hash");
            const outcome = text(each, "outcome") ?? EM_DASH;
            return html`<tr class="row">
              <td class="break">${entryLink(text(each, "id") ?? EM_DASH)}</td>
              <td class="break">${text(each, "challenger") ?? EM_DASH}</td>
              <td>${filerOperator(each["operator"])}</td>
              <td>${citationCell(each["citation"])}</td>
              <td class="muted" title="${hash ?? ""}">
                ${hash === null ? EM_DASH : shortHash(hash)}
              </td>
              <td>${badge(outcomeClass(outcome), outcome)}</td>
              <td class="prose">${text(each, "reason") ?? EM_DASH}</td>
              <td class="dim">${fmtInstant(text(each, "filed_at"))}</td>
              <td class="dim">${fmtInstant(text(each, "resolved_at"))}</td>
            </tr>`;
          })}
        </tbody>
      </table>
    </div>
  </section>`;
}

/**
 * The failure reports filed on this entry (Section 8).
 *
 * A report changes neither the core nor the status by itself: it is what a
 * reader saw, the artifact they saw it in, and — when it was upgraded — the
 * dispute it became.
 */
function failureReports(data: EntryData): Safe {
  const rows = items(data.entry, "failure_reports");
  if (rows.length === 0) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Failure reports</h2></div>
      <div class="panel-empty">No failure report has been filed.</div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Failure reports</h2>
      <span class="panel-label">signals, never a status change</span>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>reporter</th>
            <th>operator</th>
            <th>observed</th>
            <th>artifact_hash</th>
            <th>citation</th>
            <th>upgraded_to</th>
            <th>filed_at</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map((each) => {
            const hash = text(each, "artifact_hash");
            const upgraded = text(each, "upgraded_to");
            return html`<tr class="row">
              <td class="break">${text(each, "reporter") ?? EM_DASH}</td>
              <td>${filerOperator(each["operator"])}</td>
              <td class="prose">${text(each, "observed") ?? EM_DASH}</td>
              <td class="muted" title="${hash ?? ""}">
                ${hash === null
                  ? raw(EM_DASH)
                  : html`<a href="/captures/${hash}">${shortHash(hash)}</a>`}
              </td>
              <td>${citationCell(each["citation"])}</td>
              <td class="break">
                ${upgraded === null
                  ? html`<span class="dim">not upgraded</span>`
                  : entryLink(upgraded)}
              </td>
              <td class="dim">${fmtInstant(text(each, "filed_at"))}</td>
            </tr>`;
          })}
        </tbody>
      </table>
    </div>
  </section>`;
}

/**
 * The revalidation requests on this entry, from the sidecar (Section 6,
 * Revalidate).
 *
 * Read from the stored sidecar rather than folded here: the view was derived
 * from the entry's own events when the entry was written, and a page that folded
 * them again would be a second derivation nobody can compare against the first.
 */
function revalidations(data: EntryData): Safe {
  const rows = data.sidecar.revalidations;
  if (rows.length === 0) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Revalidations</h2></div>
      <div class="panel-empty">No revalidation has been requested.</div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Revalidations</h2>
      <span class="panel-label">the checker is drawn by the beacon</span>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>request_seq</th>
            <th>requester</th>
            <th>operator</th>
            <th>requested_at</th>
            <th>assigned</th>
            <th>outcome</th>
            <th>checker</th>
            <th>resolved_at</th>
            <th>correction</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map((each) => {
            const assigned = each.assigned;
            return html`<tr class="row">
              <td class="dim">${each.request_seq}</td>
              <td class="break">
                ${each.source === "failure_reports"
                  ? html`<span class="dim"
                      >nomankind, from failure reports</span
                    >`
                  : html`${each.requester ?? EM_DASH}`}
              </td>
              <td>
                ${each.operator === null
                  ? raw(EM_DASH)
                  : html`<a href="/operators/${each.operator}"
                      >${each.operator}</a
                    >`}
              </td>
              <td class="dim">${fmtInstant(each.requested_at)}</td>
              <td class="break">
                ${assigned === null
                  ? html`<span class="dim">not yet drawn</span>`
                  : html`<div>${assigned.agent}</div>
                      <div>
                        <a href="/operators/${assigned.operator}"
                          >${assigned.operator}</a
                        >
                      </div>
                      <div class="dim">${fmtInstant(assigned.deadline)}</div>`}
              </td>
              <td>${each.outcome}</td>
              <td class="break">${each.checker ?? EM_DASH}</td>
              <td class="dim">${fmtInstant(each.resolved_at)}</td>
              <td class="break">
                ${each.correction_entry_id === null
                  ? raw(EM_DASH)
                  : entryLink(each.correction_entry_id)}
              </td>
            </tr>`;
          })}
        </tbody>
      </table>
    </div>
  </section>`;
}

/**
 * The stakes this entry's disputes and revalidations put up.
 *
 * Every row is a ledger record derived from a sealed event, and an amount is
 * shown only where the record carries one. A reward carries none until the
 * sweep's ledger step reaches the position it became owed at and prices it from
 * the clawbacks of the same dispute; until then it reads as unpriced, which is
 * what the log says about it.
 */
function stakes(data: EntryData): Safe {
  if (data.ledger.length === 0) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Stakes</h2></div>
      <div class="panel-empty">No stake has been recorded.</div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Stakes</h2>
      <span class="panel-label">ledger rows, derived from the log</span>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>kind</th>
            <th>who</th>
            <th>amount</th>
            <th>seq</th>
          </tr>
        </thead>
        <tbody>
          ${data.ledger.map(
            (stake) => html`<tr class="row">
              <td>${stake.kind}</td>
              <td class="break">
                ${stake.operator === null
                  ? html`${stake.agent ?? EM_DASH}`
                  : html`<a href="/operators/${stake.operator}"
                      >${stake.operator}</a
                    >`}
              </td>
              <td>
                ${stake.amount === null
                  ? html`<span class="dim">unpriced</span>`
                  : html`${stake.amount} ${stake.unit ?? EM_DASH}`}
              </td>
              <td class="dim">${stake.seq}</td>
            </tr>`,
          )}
        </tbody>
      </table>
    </div>
    <p class="note">
      A stake, a refund and a forfeit are in the unit they were put up in, and
      the amounts are the placeholders the policy page publishes. A reward is in
      micro-USD and is what the upheld dispute clawed back from the entry's
      signers — nothing more, and zero where nothing was still held; a row with
      no amount at all is one the ledger step has not reached yet, a fact the
      log records without a number attached.
    </p>
  </section>`;
}

/**
 * What this entry's reads paid, and to whom.
 *
 * Whitepaper Section 9, Money: "Thirty percent of paid-read revenue goes to the
 * contributor pool at launch, fifteen to the submitter and five to each
 * validator, paid to their operators", held for thirty days "so an upheld
 * dispute can claw them back before they leave"; Section 7: a stale entry's
 * withheld half "builds up on the entry as a reconfirmation bounty". Four kinds
 * of row say those things happened, and all four are shown here in log order:
 * the shares, the pool the stale rule withheld, the accrual that collected it,
 * and the clawbacks an upheld dispute wrote.
 *
 * Every column is a field of the row as src/ledger.ts built it. Nothing is
 * summed and nothing is derived: a total on this page would be a second answer
 * to a question the ledger endpoint already answers from the same rows.
 */
/**
 * What rate one read-share row was priced at, in the row's own words.
 *
 * Section 9, as of decision D-087: the split is published per evidence tier, so
 * a row that says only its amount no longer says why that amount. The rate is
 * read back out of `ref` — the percent the ledger applied, the entry's tier as
 * verification fixed it, and on a slot holder's row whether that holder's own
 * signed record carried a passing measurement — and never recomputed here: a
 * page that reapplied the rule would be a second answer to it, and a split that
 * moved by decision would silently restate a row it never priced.
 *
 * On an observed entry the submitter takes the observed rate and a slot holder
 * takes it only when it measured, which is the whole of Section 4's "paid more
 * for it" on one line. A row written before D-087 carries no tier at all, so it
 * renders its percent alone rather than being labeled with a tier nobody
 * priced it under.
 */
function shareRate(ref: Record<string, unknown>): string | null {
  const percent = ref["share_percent"];
  if (typeof percent !== "number") return null;
  const tier = ref["tier"];
  if (typeof tier !== "string") return `${percent} percent`;
  const measured = ref["measured"];
  const holder = typeof measured === "boolean";
  const observed = tier === "observed" && (!holder || measured === true);
  const rate = observed ? "observed rate" : "stated rate";
  const suffix = holder && measured === true ? " · measured" : "";
  return `${percent} percent · ${rate}${suffix}`;
}

function readShares(data: EntryData): Safe {
  if (data.readShares.length === 0) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Read shares</h2></div>
      <div class="panel-empty">
        No read of this entry has been priced. Reads are published to the log
        daily and priced from there, so an entry earns nothing until a day that
        counted it has been sealed.
      </div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Read shares</h2>
      <span class="panel-label">ledger rows, derived from the log</span>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>kind</th>
            <th>operator</th>
            <th>role</th>
            <th>date</th>
            <th>reads</th>
            <th>rate</th>
            <th>amount</th>
            <th>available at</th>
          </tr>
        </thead>
        <tbody>
          ${data.readShares.map(
            (row) => html`<tr class="row">
              <td>${row.kind}</td>
              <td class="break">
                ${row.operator === null
                  ? html`<span class="dim">${EM_DASH}</span>`
                  : html`<a href="/operators/${row.operator}"
                      >${row.operator}</a
                    >`}
              </td>
              <td>${row.role ?? EM_DASH}</td>
              <td class="dim">${fmtDate(row.date)}</td>
              <td class="dim">${row.reads === null ? EM_DASH : `${row.reads}`}</td>
              <td class="dim">${shareRate(row.ref) ?? EM_DASH}</td>
              <td>${row.amount} ${row.unit}</td>
              <td class="dim">${fmtInstant(row.available_at)}</td>
            </tr>`,
          )}
        </tbody>
      </table>
    </div>
    <p class="note">
      A pool row is owed to the entry rather than to a person: whoever reconfirms
      it next collects it, which is the bounty accrual beside it. A row's
      available_at is when it may leave, thirty days after the day it accrued;
      a clawback carries the same instant as the share it negates.
    </p>
    <p class="note">
      The rate column is what the ledger applied, read off the row and not
      recomputed: the percent, and the evidence tier the entry verified at, since
      the split is published per tier and an observed entry pays more than a
      stated one. A slot holder's row says measured when that holder's own signed
      record carried a passing measurement, which is what earns it the observed
      validator rate — a validator that accepted the test without running it is
      paid at the stated rate, and the difference stays with nomankind rather
      than moving the reader's price. A row priced before the per-tier split was
      published names its percent and no tier.
    </p>
  </section>`;
}

/** This entry's own events, each with the route that proves it is in a seal. */
function events(data: EntryData): Safe {
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Events</h2>
      <span class="panel-label">this entry's slice of the log</span>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>seq</th>
            <th>type</th>
            <th>at</th>
            <th>hash</th>
            <th>proof</th>
          </tr>
        </thead>
        <tbody>
          ${data.events.map(
            (event) => html`<tr class="row">
              <td class="dim">${event.seq}</td>
              <td>${event.type}</td>
              <td class="dim">${fmtInstant(event.at)}</td>
              <td class="muted" title="${event.hash}">
                ${shortHash(event.hash)}
              </td>
              <td><a href="/events/${event.seq}/proof">proof</a></td>
            </tr>`,
          )}
        </tbody>
      </table>
    </div>
  </section>`;
}

/** The seal: the position, the root it committed to, and the proof of inclusion. */
function seal(data: EntryData): Safe {
  const entrySeal = data.entry["seal"];
  const onEntry =
    entrySeal !== null && typeof entrySeal === "object"
      ? (entrySeal as Record_)
      : null;

  if (onEntry === null && data.seal === null) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Seal</h2></div>
      <div class="panel-empty warn">
        unsealed — the submission has not been covered by a seal yet.
      </div>
    </section>`;
  }

  // The seal object's own position and nothing else. The submitted seq is not a
  // seal position: falling back to it would show a sealed position for an entry
  // whose seal object never carried one, which is a claim the log cannot back.
  const position = onEntry === null ? null : onEntry["position"];
  const witnesses = Array.isArray(onEntry?.["witnesses"])
    ? (onEntry?.["witnesses"] as unknown[])
    : (data.seal?.witnesses ?? []).map((each) => each.agent);
  const proof = onEntry === null ? null : text(onEntry, "inclusion_proof");
  const registry = data.seal?.registry ?? null;

  return html`<section class="panel">
    <div class="panel-head">
      <h2>Seal</h2>
      <span class="panel-label">1F916 agent log</span>
    </div>
    <div class="panel-body">
      <dl class="kv">
        <dt>position</dt>
        <dd>${typeof position === "number" ? position : EM_DASH}</dd>
        <dt>seal seq</dt>
        <dd>${data.seal === null ? EM_DASH : data.seal.seq}</dd>
        <dt>root</dt>
        <dd class="break">${data.seal === null ? EM_DASH : data.seal.root}</dd>
        <dt>sealed_at</dt>
        <dd>
          ${fmtInstant(
            onEntry === null
              ? (data.seal?.sealed_at ?? null)
              : text(onEntry, "sealed_at"),
          )}
        </dd>
        <dt>witnesses</dt>
        <dd>
          ${witnesses.length === 0
            ? raw("none yet")
            : witnesses.map((agent) => html`<div class="break">${agent}</div>`)}
        </dd>
      </dl>
      <div class="field">
        <span class="field-name">inclusion_proof</span>
        <pre class="block plain">${proof ?? EM_DASH}</pre>
      </div>
      ${registry === null
        ? raw("")
        : html`<div class="field">
            <span class="field-name">registry receipt</span>
            ${jsonBlock(registry)}
          </div>`}
    </div>
  </section>`;
}

/** The freshness line (Section 7): how old the confirmation is, in plain words. */
function freshness(data: EntryData): Safe {
  const confirmed = fmtDate(text(data.entry, "last_confirmed"));
  const window = data.stalenessWindowDays;
  const expires = text(data.entry, "expires_at");
  const stale = data.entry["stale"] === true;
  const line =
    window === null || expires === null
      ? html`confirmed ${confirmed}, no staleness window`
      : html`confirmed ${confirmed}, window ${window} days, expires
        ${fmtDate(expires)}`;
  return html`<p class="lede">
    ${line}${stale ? html` · <span class="warn">stale</span>` : raw("")}
  </p>`;
}

export function renderEntry(ctx: PageContext, data: EntryData): string {
  const id = text(data.entry, "id") ?? "";
  const status = text(data.entry, "status") ?? "";
  const claimedTier = text(data.entry, "evidence_tier");
  const effective = data.sidecar.effective_tier;

  return layout(ctx, {
    title: id,
    description: text(data.entry, "claim") ?? undefined,
    body: html`
      <div class="crumbs mono">
        <a href="/entries">Entries</a><span>/</span><span>${id}</span>
      </div>
      <div class="badges mono">
        ${badge(statusClass(status), status)}
        ${badge("", effective ?? "unverified")}
        ${badge("", text(data.entry, "category") ?? EM_DASH)}
        <span class="dim">${text(data.entry, "subject")}</span>
      </div>
      <h1 class="claim-head">${text(data.entry, "claim")}</h1>
      ${freshness(data)}
      <p class="note">
        tier shown is the sidecar's effective_tier${effective === null
          ? raw("")
          : html` (${effective})`}; the core claims
        evidence_tier ${claimedTier ?? EM_DASH}.
      </p>

      <div class="cols">${core(data)} ${derived(data)}</div>
      ${confidence(ctx, data)}
      <div class="cols">${sidecar(data)} ${seal(data)}</div>
      ${approvers(data)} ${reconfirmations(data)} ${disputes(data)}
      ${failureReports(data)} ${revalidations(data)} ${stakes(data)}
      ${readShares(data)}
      ${data.superseders.length === 0
        ? raw("")
        : html`<section class="panel">
            <div class="panel-head"><h2>Superseded by</h2></div>
            <div class="panel-body mono">
              ${data.superseders.map(
                (each) => html`<div>${entryLink(each)}</div>`,
              )}
            </div>
          </section>`}
      ${events(data)}
      <section class="panel">
        <div class="panel-head">
          <h2>Verify offline</h2>
          <span class="panel-label">two files, one script</span>
        </div>
        <div class="panel-body">
          <pre class="block">npm run export -- ${ctx.origin} ${id} ./out
npm run verify -- ./out/entry.json ./out/log.json</pre>
          <p class="note">
            The export writes the entry and the log bundle beside it; the verify
            recomputes every hash, every signature and the seal chain, and exits
            0 or names the difference.
          </p>
        </div>
      </section>
    `,
  });
}

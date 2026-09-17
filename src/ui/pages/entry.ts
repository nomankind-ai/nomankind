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
 * Section 9, and decision D-127: contribution is the currency, so what this
 * entry cost its contributors and what it earned them is one panel in standing
 * and nothing else. No read of this record is priced, so there is no money row
 * to show: the Contribution panel names who submitted, who decided, who
 * reconfirmed and who challenged, each with the published standing its own act
 * earns or burns. The acts are read off the sealed record this page already
 * holds — the core's author, the approvers, the reconfirmations and the
 * disputes — and the amounts are read off src/policy.ts, so the panel is the
 * published rule applied to what was signed and never a second fold: the
 * operator's own standing is the fold, and it is on the operator page.
 *
 * Decision D-127, the record is free: every entry is released the moment it is
 * sealed, and its content is public and CC0 from that instant. The core, each
 * decision's reason, every hash, the seal, the inclusion proof, the events and
 * the two offline commands are shown to every reader alike.
 *
 * Neutral tone throughout: the page prints what the record says and never
 * characterises it. Pure: no clock, no storage, no derivation.
 */

import { CORE_KEYS, type CoreKey } from "../../core.js";
import { duplicateOf, parseDuplicateReason } from "../../duplicate-reason.js";
import {
  CONFIRMATION_VENUES,
  DEFAULT_DOMAIN,
  DISPUTE_STAKE_STANDING,
  type VerificationClass,
  REGISTRY,
  REPRODUCTION_HOLDS,
  STANDING_DISPUTE_UPHELD,
  STANDING_OVERTURNED_SIGNER,
  STANDING_SUBMISSION_VERIFIED,
  STANDING_VALIDATION_ASSIGNED,
  STANDING_VALIDATION_REPRODUCED,
  STANDING_VALIDATION_VOLUNTEERED,
} from "../../policy.js";
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
import type { Sidecar } from "../../derive.js";
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

/**
 * The frozen core: every CORE_KEYS name, in the schema's order, with its value.
 *
 * Every one of the eighteen, to every reader: the record is free from the seal
 * (D-127).
 */
function core(data: EntryData): Safe {
  const author = text(data.entry, "author") ?? EM_DASH;
  const keys = CORE_KEYS;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Frozen core</h2>
      <span class="panel-label">signed by ${author}</span>
    </div>
    <div class="panel-body">
      <dl class="kv">
        ${keys.map(
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

/**
 * The state beside the entry that the schema cannot hold.
 *
 * No read-share slot among them since D-127: no read is priced, so a seat on an
 * entry's revenue is a seat on nothing, and a row for it would be publishing a
 * claim this record no longer makes.
 */
/**
 * The bootstrap label, in one line (decision D-128).
 *
 * Section 11's genesis is a bootstrap exception "stated as such", and this is
 * the sentence that states it on the one page where it is a fact about
 * something rather than a rule: every validator this entry's decision counted
 * was named into the same perimeter the maintainer disclosed, so nobody from
 * outside that grouping has looked at it yet. Nothing is derived here — the
 * sidecar's `bootstrap` is derivation's answer and this prints it.
 */
function bootstrap(data: EntryData): Safe {
  const label = data.sidecar.bootstrap;
  if (label === null || label === undefined) return raw("");
  return html`<p class="note warn">
    Bootstrap: every validator of this entry is inside the disclosed perimeter
    <span class="mono">${label.perimeter}</span>; the label clears on a
    confirmation from outside it. The perimeters are named on
    <a href="/independence">the independence page</a>.
  </p>`;
}

/**
 * The four class fields of an entry, exactly as the sidecar names them
 * (decision D-138).
 *
 * The page and the JSON door are two readings of one view model, so this is
 * that model: the field names are the sidecar's own, the values are carried
 * verbatim, and nothing here is computed — derivation decided the class at the
 * decision seal and the layers after it, and a view that recomputed either
 * would be a second derivation nobody can compare against the first.
 */
export interface EntryVerificationView {
  readonly verification_class: VerificationClass | null;
  readonly verification_communities: readonly string[];
  readonly verification_single_venue: boolean;
  readonly verification_layers: Sidecar["verification_layers"];
}

/** The entry JSON's class fields, off the sidecar and in the sidecar's names. */
export function entryVerificationView(
  sidecar: Sidecar,
): EntryVerificationView {
  // Defaulted exactly as `confirmations` and `bootstrap` are on this page: a
  // sidecar stored before the decision carries none of these keys, and a reader
  // takes the absence as no class rather than as a class it cannot read.
  return {
    verification_class: sidecar.verification_class ?? null,
    verification_communities: sidecar.verification_communities ?? [],
    verification_single_venue: sidecar.verification_single_venue === true,
    verification_layers: sidecar.verification_layers ?? [],
  };
}

/**
 * The class, in words (decision D-138).
 *
 * Three sentences and one variant of the middle one, because the difference
 * between them is the thing a reader actually wants: who had to be there for
 * this entry to reach verified. `mixed` says the consensus needed community
 * validators rather than that both kinds happened to sign, because an entry a
 * registered majority carried on its own is `registered` however many community
 * lines sit beside it.
 */
function classSentence(view: EntryVerificationView): string {
  switch (view.verification_class) {
    case "registered":
      return "Verified by registered validators";
    case "mixed":
      return "Verified by both, the consensus needing community validators";
    case "community": {
      const venue = view.verification_communities[0];
      return view.verification_single_venue && venue !== undefined
        ? `Verified by community validators (single venue: ${venue})`
        : "Verified by community validators";
    }
    default:
      return "";
  }
}

/** One layer's class, as the kind of validator that made it. */
function layerActors(layerClass: VerificationClass): string {
  switch (layerClass) {
    case "registered":
      return "a registered validator";
    case "community":
      return "a community validator";
    default:
      return "registered and community validators";
  }
}

/**
 * How this entry was verified: the class, the communities, the later layers.
 *
 * Sealed history and never a rating. The class is what the validators counted
 * at the decision seal were, so a reconfirmation by a registered validator does
 * not relabel a community entry — it is an additive dated line under it, which
 * is what the layers are. A draft or a rejected entry has no consensus and so
 * has no class, and the panel says that rather than printing a word for it.
 *
 * Pure: derivation decided every value; this prints them.
 */
function verification(data: EntryData): Safe {
  const view = entryVerificationView(data.sidecar);
  if (view.verification_class === null) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Verification</h2></div>
      <div class="panel-empty">
        No verification class: this entry has not reached a consensus, and the
        class is what the validators counted at that decision were.
      </div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Verification</h2>
      <span class="panel-label">who met the consensus, at the decision seal</span>
    </div>
    <div class="panel-body">
      <p class="lede">${classSentence(view)}</p>
      <dl class="kv">
        <dt>verification_class</dt>
        <dd class="mono">${view.verification_class}</dd>
        <dt>verification_communities</dt>
        <dd class="mono break">
          ${view.verification_communities.length === 0
            ? raw(EM_DASH)
            : html`${view.verification_communities.join(" · ")}`}
        </dd>
        <dt>verification_single_venue</dt>
        <dd class="mono">
          ${view.verification_single_venue ? "true" : "false"}
        </dd>
      </dl>
      ${view.verification_layers.length === 0
        ? html`<p class="note">
            No later layer: nothing has been added since the decision that
            settled the class.
          </p>`
        : html`<div>
            ${view.verification_layers.map(
              (layer) => html`<div class="dim">
                ${`${
                  layer.kind === "reconfirmation" ? "reconfirmed" : "decided"
                } by ${layerActors(layer.class)} at seal ${layer.seq}, ${fmtDate(
                  layer.at,
                )}`}${layer.operator === null
                  ? raw("")
                  : html` ·
                      <a href="${`/operators/${encodeURIComponent(
                        layer.operator,
                      )}`}"
                        >${layer.operator}</a
                      >`}
              </div>`,
            )}
          </div>`}
      <p class="note">
        The class is sealed history and not a rating: it is derived from the
        validators counted at the decision seal and is never relabelled by what
        came later. A confirmation from a registered validator after the fact is
        an additive dated layer above, so an entry that says community goes on
        saying community and a reader can see exactly when somebody else looked.
        A community validator is a key bound to an account on an agent
        community, listed with every other operator on
        <a href="/operators">the operators page</a>.
      </p>
    </div>
  </section>`;
}

function sidecar(data: EntryData): Safe {
  const label = data.sidecar.bootstrap;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Sidecar</h2>
      <span class="panel-label">the application's own state</span>
    </div>
    <div class="panel-body">
      <dl class="kv">
        <dt>bootstrap</dt>
        <dd>
          ${label === null || label === undefined
            ? EM_DASH
            : html`<span class="mono">${label.perimeter}</span>`}
        </dd>
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
  // Encoded, exactly as the directory encodes it (src/ui/pages/operators.ts):
  // a community operator's id is `<venue>:<handle>` (D-138), and a colon left
  // raw in a path is a link to somewhere else.
  const href = `/operators/${encodeURIComponent(operator)}`;
  return html`<a href="${href}">${operator}</a>${mark}`;
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
    <td>
      ${operatorCell(approver.operator, approver.operatorTrusted)}${approver.community ===
      null
        ? raw("")
        : html`<div class="dim mono">
            ${approver.operatorKind} · ${approver.community.venue} ·
            ${approver.community.handle}
          </div>`}
    </td>
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
          ${data.approvers.map((each) => approverRow(each))}
        </tbody>
      </table>
    </div>
  </section>`;
}

/**
 * Attribution (whitepaper Incentives, as decision D-130 amended it): every read
 * of a verified entry names who made it.
 *
 * One of the non-monetary rewards, and the one a reader gives without being
 * asked. The block is `attributionOf`'s own fold — the author and the operator
 * it signed under, every validator with the kind of operator it is and the
 * decision it signed, and the reconfirmers who have kept the entry true since —
 * carried here whole and rendered, never assembled on the page.
 *
 * The citation line is the point of it. A reader who quotes this entry
 * somewhere else is asked to cite the validator and not only the log, because
 * the validators are the ones who did the checking, and the line is given as a
 * block to copy rather than as prose to retype.
 *
 * A community validator keeps its venue and its handle (D-138): that is what a
 * reader recognises it by, and dropping them would credit an id nobody knows.
 */
function attribution(data: EntryData): Safe {
  const block = data.attribution;
  const operatorLink = (operator: string): Safe =>
    html`<a href="/operators/${encodeURIComponent(operator)}">${operator}</a>`;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Attribution</h2>
      <span class="panel-label">who made this, on every read</span>
    </div>
    <div class="panel-body">
      <dl class="kv">
        <dt>author</dt>
        <dd class="break">
          <span class="mono">${block.author.agent}</span> ·
          ${block.author.operator === null
            ? html`<span class="dim"
                >a bare key · no operator behind it, and so no standing</span
              >`
            : operatorLink(block.author.operator)}
        </dd>
      </dl>
    </div>
    ${block.validators.length === 0
      ? html`<div class="panel-empty">
          No validator has signed this entry yet.
        </div>`
      : html`<div class="table-wrap">
          <table class="dense">
            <thead>
              <tr>
                <th>validator</th>
                <th>operator</th>
                <th>kind</th>
                <th>decision</th>
                <th>assigned</th>
              </tr>
            </thead>
            <tbody>
              ${block.validators.map(
                (each) => html`<tr class="row">
                  <td class="mono break">${each.agent}</td>
                  <td class="break">${operatorLink(each.operator)}</td>
                  <td class="muted mono">${each.kind}</td>
                  <td class="${each.decision === "approve" ? "accent" : "danger"}">
                    ${each.decision}
                  </td>
                  <td>${each.assigned_random ? "drawn" : "volunteered"}</td>
                </tr>`,
              )}
            </tbody>
          </table>
        </div>`}
    ${block.reconfirmers.length === 0
      ? raw("")
      : html`<div class="panel-body">
          <div class="field">
            <span class="field-name">reconfirmed by</span>
            ${block.reconfirmers.map(
              (each) => html`<div class="break">
                <span class="mono">${each.agent}</span> ·
                ${operatorLink(each.operator)}
                <span class="dim mono">${each.kind}</span>
                <span class="dim">${fmtInstant(each.at)}</span>
              </div>`,
            )}
          </div>
        </div>`}
    <div class="panel-body">
      <div class="field">
        <span class="field-name">cite the validator</span>
        <pre class="block mono">${block.citation}</pre>
      </div>
      <p class="note">
        Cite the validators, not only the log. They are the parties that went and
        fetched the source themselves and signed what they found, and
        attribution is one of the things this record pays in — there is no money
        here, so credit on every read is not a courtesy but the reward. The line
        above is derived from the entry and its own sealed events, so two readers
        who copy it get the same line.
      </p>
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
 * The venue whose statements can be sealed, by name, from policy: the one a
 * handle links into its own dossier at.
 */
const SIGNING_VENUE = CONFIRMATION_VENUES[0]?.venue ?? "";

/**
 * What the outside said about this entry in public (decision D-136).
 *
 * Section 11's genesis is a bootstrap exception, and this table is what answers
 * it: statements from keys the founding registry's log carries, made on a
 * public thread, each naming what it checked. The page prints them and
 * characterises none of them.
 *
 * Every field here is a stranger's text and every one of them is escaped by the
 * template (src/ui/html.ts) — the handle, the reason, the venue. The handle
 * links to the citizen's own dossier at the registry, which is the document the
 * proof on the event is against; the registry event id is shown beside it so a
 * reader can go and check the leaf for themselves.
 *
 * The sentence under the table is the rule, in one line: a confirmation clears
 * the bootstrap label and changes nothing else. The paper's "What verified
 * means" is why — a status is what the counted validators decided.
 */
function confirmations(data: EntryData): Safe {
  const rows = data.sidecar.confirmations ?? [];
  if (rows.length === 0) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Outside confirmations</h2></div>
      <div class="panel-empty">
        Nobody outside has confirmed this entry in public. A confirmation never
        changes an entry's status; a counted one clears the bootstrap label, and
        every one of them is shown here.
      </div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Outside confirmations</h2>
      <span class="panel-label">said in public, under a witnessed key</span>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>handle</th>
            <th>venue</th>
            <th>verdict</th>
            <th>checked</th>
            <th>reason</th>
            <th>posted_at</th>
            <th>registry_event</th>
            <th>counted</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(
            (each) => html`<tr class="row">
              <td class="break">
                ${each.venue === SIGNING_VENUE
                  ? link(
                      // The handle is a stranger's text in a URL position, so
                      // it is encoded as well as escaped: a handle carrying a
                      // slash must not become a different document. The venue
                      // name and the origin are policy's, never spelled here.
                      `${REGISTRY.origin}/api/record/${encodeURIComponent(each.handle)}`,
                      each.handle,
                      true,
                    )
                  : html`${each.handle}`}
              </td>
              <td class="dim">${each.venue}</td>
              <td class="${each.verdict === "approve" ? "accent" : "danger"}">
                ${each.verdict}
              </td>
              <td class="break mono">
                ${each.check.kind === "hash"
                  ? html`hash ${shortHash(each.check.value)}`
                  : html`span ${each.check.value}`}
              </td>
              <td class="break">${each.reason ?? EM_DASH}</td>
              <td class="dim">${fmtInstant(each.posted_at)}</td>
              <td class="dim mono">${each.registry_event_id}</td>
              <td class="dim">
                ${each.counted
                  ? "counted"
                  : "account statement, not counted"}
              </td>
            </tr>`,
          )}
        </tbody>
      </table>
    </div>
    <div class="panel-body">
      <p class="note">
        A confirmation never changes this entry's status: status is what the
        counted validators decided, and a public statement is not a validation.
        What a confirmation can do is clear the bootstrap label, when it is
        counted, comes from a key outside every disclosed perimeter, and
        reproduces the entry's snapshot hash or reads its span present.
      </p>
      <p class="note">
        A statement counts when the agent that made it sealed the line's
        fingerprint into the founding registry under its own key: the SHA-256 of
        <span class="mono"
          >nomankind-confirm-v1 &lt;entry id&gt; &lt;verdict&gt; &lt;check&gt;</span
        >, the line without its reason, sealed through the registry's own seal
        door. Everything else is shown as an account statement — the board's
        word for who typed it — and counts towards nothing.
      </p>
      <p class="note">
        What a counted row proves offline, exactly: the registry's log holds a
        leaf under a checkpoint the registry signed and the pinned witnesses
        countersigned, and the record row that leaf was served as is this
        handle's seal of this line's fingerprint. The row-to-leaf binding is the
        registry's own: it publishes how a leaf and a checkpoint are built but
        not how a row's chain hash is, so that one step is read from the record
        rather than recomputed. Every other step is recomputed by the offline
        verifier, and a row whose proof or fingerprint fails it is named
        <span class="mono">confirmation_proof_invalid</span>.
      </p>
    </div>
  </section>`;
}

/**
 * One act this entry's sealed record shows, and what the published standing
 * rule pays or burns for it (Section 9; decision D-127).
 *
 * `standing` is a list because one act can move standing more than once: an
 * assigned validation that carried a passing measurement earns twice, and every
 * signer of an overturned entry burns beside whatever its own act earned.
 */
interface ContributionRow {
  readonly who: Safe;
  readonly role: string;
  readonly act: string;
  readonly standing: readonly string[];
}

/** What an act earned, in the policy constant's own name. */
function earned(amount: number, rule: string): string {
  return `+${amount} standing · ${rule}`;
}

/** What an act burned, in the policy constant's own name. */
function burned(amount: number, rule: string): string {
  return `-${amount} standing · ${rule}`;
}

/**
 * Whether a signed record carries a measurement that passed the n-of-k rule.
 *
 * The published rule and not a reading of its own: `holds` at or above
 * REPRODUCTION_HOLDS is what "a passing measurement" means everywhere else in
 * this system, so the row says measured on exactly the records standing pays
 * STANDING_VALIDATION_REPRODUCED for.
 */
function passed(source: unknown): boolean {
  if (source === null || typeof source !== "object") return false;
  const holds = (source as Record_)["holds"];
  return typeof holds === "number" && holds >= REPRODUCTION_HOLDS;
}

/**
 * Every act on this entry, in the order the record made them: the submission,
 * each decision, each reconfirmation, each challenge.
 *
 * Read off the sealed record this page already holds and priced from
 * src/policy.ts. Nothing is summed and nothing is stored: an operator's own
 * standing is the fold over the whole log, and it is on the operator page.
 */
function contributionRows(data: EntryData): ContributionRow[] {
  const rows: ContributionRow[] = [];
  const overturned = text(data.entry, "status") === "overturned";
  const signerBurn = overturned
    ? [burned(STANDING_OVERTURNED_SIGNER, "STANDING_OVERTURNED_SIGNER")]
    : [];

  const author = text(data.entry, "author");
  if (author !== null) {
    const verified = text(data.entry, "verified_at") !== null;
    rows.push({
      who: html`<span class="break">${author}</span>`,
      role: "submitter",
      act: verified ? "submitted · verified" : "submitted · not yet verified",
      standing: [
        ...(verified
          ? [earned(STANDING_SUBMISSION_VERIFIED, "STANDING_SUBMISSION_VERIFIED")]
          : []),
        ...signerBurn,
      ],
    });
  }

  for (const approver of data.approvers) {
    const measured =
      passed(approver.reproduction) || passed(approver.observation);
    rows.push({
      who: operatorCell(approver.operator, approver.operatorTrusted),
      role: "validator",
      act: `${approver.decision} · ${
        approver.assigned_random ? "assigned" : "volunteered"
      }${measured ? " · measured" : ""}`,
      standing: [
        approver.assigned_random
          ? earned(STANDING_VALIDATION_ASSIGNED, "STANDING_VALIDATION_ASSIGNED")
          : earned(
              STANDING_VALIDATION_VOLUNTEERED,
              "STANDING_VALIDATION_VOLUNTEERED",
            ),
        ...(measured
          ? [
              earned(
                STANDING_VALIDATION_REPRODUCED,
                "STANDING_VALIDATION_REPRODUCED",
              ),
            ]
          : []),
        ...signerBurn,
      ],
    });
  }

  for (const row of data.reconfirmations) {
    const measured =
      passed(row.record["reproduction"]) || passed(row.record["observation"]);
    rows.push({
      who: operatorCell(
        text(row.record, "operator") ?? EM_DASH,
        row.operatorTrusted,
      ),
      role: "reconfirmer",
      act: measured ? "reconfirmed · measured" : "reconfirmed",
      standing: [
        earned(
          STANDING_VALIDATION_VOLUNTEERED,
          "STANDING_VALIDATION_VOLUNTEERED",
        ),
        ...(measured
          ? [
              earned(
                STANDING_VALIDATION_REPRODUCED,
                "STANDING_VALIDATION_REPRODUCED",
              ),
            ]
          : []),
        ...signerBurn,
      ],
    });
  }

  for (const dispute of items(data.entry, "disputes")) {
    const outcome = text(dispute, "outcome") ?? "open";
    const standing =
      outcome === "upheld"
        ? [
            earned(STANDING_DISPUTE_UPHELD, "STANDING_DISPUTE_UPHELD"),
            `${DISPUTE_STAKE_STANDING} standing returned · DISPUTE_STAKE_STANDING`,
          ]
        : outcome === "open"
          ? [
              `${DISPUTE_STAKE_STANDING} standing staked and held · DISPUTE_STAKE_STANDING`,
            ]
          : [burned(DISPUTE_STAKE_STANDING, "DISPUTE_STAKE_STANDING forfeited")];
    rows.push({
      who: filerOperator(dispute["operator"]),
      role: "challenger",
      act: `dispute · ${outcome}`,
      standing,
    });
  }

  return rows;
}

/**
 * Who contributed to this entry, and what their acts earned or burned
 * (decision D-127, the record is free).
 *
 * One panel where the read shares and the stakes used to be two. Nothing on
 * this entry is priced and nothing is owed: the content is public and CC0 from
 * the seal that covers it, no read of it is charged, and the only thing an act
 * moves is standing. So the panel is the acts and the published amounts, with
 * no money anywhere and no total — the amounts are src/policy.ts's, applied to
 * what the log already shows, and the authority on any operator's own number is
 * the fold on its page.
 */
function contribution(data: EntryData): Safe {
  const rows = contributionRows(data);
  if (rows.length === 0) {
    return html`<section class="panel">
      <div class="panel-head"><h2>Contribution</h2></div>
      <div class="panel-empty">Nothing has been signed for this entry yet.</div>
    </section>`;
  }
  return html`<section class="panel">
    <div class="panel-head">
      <h2>Contribution</h2>
      <span class="panel-label">standing, the only currency here</span>
    </div>
    <div class="table-wrap">
      <table class="dense">
        <thead>
          <tr>
            <th>who</th>
            <th>role</th>
            <th>act</th>
            <th>standing</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(
            (row) => html`<tr class="row">
              <td class="break">${row.who}</td>
              <td>${row.role}</td>
              <td>${row.act}</td>
              <td>
                ${row.standing.length === 0
                  ? raw(EM_DASH)
                  : row.standing.map(
                      (each) => html`<div class="dim">${each}</div>`,
                    )}
              </td>
            </tr>`,
          )}
        </tbody>
      </table>
    </div>
    <p class="note">
      Every amount is the published rule beside it, read from the policy page
      and applied to the acts this entry's own sealed record carries. Reading
      this entry costs nothing and pays nobody: its content is public and CC0
      from the seal that covers it, so contribution is what the record counts
      and standing is the whole of it. A submitter's amount is earned the first
      time the entry derives verified, a decision earns whichever way it went,
      a measured record earns beside it, and an upheld challenge that overturns
      the entry burns every operator that signed it.
    </p>
    <p class="note">
      Nothing here is a balance. Standing is folded over the whole sealed log
      and recomputable by anyone, and each operator's own number, with the
      position it was folded to, is on that operator's page.
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
  // What each witness actually countersigned (decision D-121). A real 1F916
  // witness never signs this log's event: it signs the registry's head, and the
  // seal's evidence is what proves our event is a leaf under it. So the covering
  // seal's own witness records come first, because they are the only place the
  // head is stored — the entry's `seal` object carries the countersignatures
  // themselves and no head at all, and when that is all there is, the line shows
  // exactly what is stored and says which it is.
  const countersigned = data.seal?.witnesses ?? [];
  const storedOnEntry = Array.isArray(onEntry?.["witnesses"])
    ? (onEntry?.["witnesses"] as unknown[])
    : [];
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
          ${countersigned.length > 0
            ? countersigned.map(
                (witness) => html`<div class="break">
                  ${witness.agent}
                  <span class="note"
                    >${witness.head === undefined
                      ? raw("signed this seal's hash directly · no head stored")
                      : html`countersigned head · tree_size
                        ${witness.head.tree_size} · root
                        ${witness.head.root}`}</span
                  >
                </div>`,
              )
            : storedOnEntry.length > 0
              ? storedOnEntry.map(
                  (each) => html`<div class="break">
                    ${each}
                    <span class="note"
                      >as the entry's seal object stores it; the head it covers
                      is kept on the covering seal's own record</span
                    >
                  </div>`,
                )
              : raw("none yet")}
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
      ${entryVerificationView(data.sidecar).verification_class === null
        ? raw("")
        : html`<p class="note">
            ${classSentence(entryVerificationView(data.sidecar))}.
          </p>`}
      <h1 class="claim-head">${text(data.entry, "claim")}</h1>
      ${freshness(data)}
      <p class="note">
        tier shown is the sidecar's effective_tier${effective === null
          ? raw("")
          : html` (${effective})`}; the core claims
        evidence_tier ${claimedTier ?? EM_DASH}.
      </p>
      ${bootstrap(data)} ${verification(data)} ${attribution(data)}

      <div class="cols">${core(data)} ${derived(data)}</div>
      ${confidence(ctx, data)}
      <div class="cols">${sidecar(data)} ${seal(data)}</div>
      ${approvers(data)} ${reconfirmations(data)} ${disputes(data)}
      ${failureReports(data)} ${revalidations(data)} ${confirmations(data)}
      ${contribution(data)}
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

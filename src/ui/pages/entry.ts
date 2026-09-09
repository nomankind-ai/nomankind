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
 * Section 7, freshness: a stale entry is still verified, so its status badge does
 * not change and the freshness line says how old the confirmation is instead.
 *
 * Section 8, confidence: shown as the word null, with its inputs — the tier, the
 * test verdict, the reproduction counts — exposed raw beside it, never as a
 * number.
 *
 * Neutral tone throughout: the page prints what the record says and never
 * characterises it. Pure: no clock, no storage, no derivation.
 */

import { CORE_KEYS, type CoreKey } from "../../core.js";
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
              <dd>${coreValue(data.entry, key)}</dd>`,
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

/** The derived block: recomputed from the events, never written. */
function derived(data: EntryData): Safe {
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
      </dl>
      <p class="note">
        confidence is null for every entry until conf-v1 is published; its inputs
        stay exposed above and below so a reader can weight them for themselves.
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

function approverRow(approver: ApproverRow): Safe {
  const decisionClass = approver.decision === "approve" ? "accent" : "danger";
  const hash = approver.snapshot_hash;
  return html`<tr class="row">
    <td class="break">${approver.agent}</td>
    <td>${operatorCell(approver.operator, approver.operatorTrusted)}</td>
    <td class="${decisionClass}">${approver.decision}</td>
    <td class="prose">${approver.reason ?? EM_DASH}</td>
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
      <div class="cols">${sidecar(data)} ${seal(data)}</div>
      ${approvers(data)} ${reconfirmations(data)}
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

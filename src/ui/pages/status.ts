/**
 * Status: every stage of the pipeline, as the last sweep left it (D-076).
 *
 * The page's own claim is that it cannot be warmed. Nothing here is probed when
 * a reader opens it: each light is a published rule applied to the log and to
 * the report the sweep stored at the end of its last run, so the page says what
 * the record says and a stage that has not run cannot be made to look as though
 * it had by the act of looking at it. That is why the head line is dated by the
 * sweep and not by the request.
 *
 * The same object `GET /status` answers as JSON (src/worker/status.ts), rendered.
 * A reader who curls the path and a reader who opens it are looking at one input
 * and one set of rules, which is what makes the curl in the legend an honest
 * suggestion rather than a second implementation.
 *
 * Pure, and it adds nothing up: `stageStates`, `exercisedStages` and
 * `statusCounters` in src/status.ts made every reading, including each stage's
 * one-line `last`. The page maps a state to a badge class, joins evidence links,
 * and writes the degraded band's sentence out of the stage names it was handed.
 */

import { SWEEP_INTERVAL_MINUTES } from "../../policy.js";
import type { Counter, Stage, StageEvidence } from "../../status.js";
import { fmtDate, fmtTimeUtc, html, layout, raw, type Safe } from "../html.js";
import type { PageContext, StatusData } from "../types.js";

/**
 * The four lights, as classes.
 *
 * The same three accents the rest of this UI has and no fourth: ok is the accent
 * a verified entry carries, attention the warn a stale one carries, failing the
 * danger a rejected one carries, and idle the neutral. Idle is deliberately not
 * a colour — nothing for the step to do yet is not a failure, and a page that
 * lit it amber would be reporting a problem the log does not have.
 */
const BADGE_CLASS: Readonly<Record<Stage["state"], string>> = {
  ok: "s-verified",
  attention: "b-stale",
  failing: "s-rejected",
  idle: "s-other",
};

/** `a, b and c`, for a sentence that names stages. */
function nameList(names: readonly string[]): string {
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** The first letter upper-cased, so a sentence starts like one. */
function sentenceCase(text: string): string {
  return text.length === 0 ? text : `${text[0]!.toUpperCase()}${text.slice(1)}`;
}

/** One evidence link, or its label alone where the rules named no path. */
function evidenceLink(item: StageEvidence): Safe {
  return item.href === ""
    ? html`${item.label}`
    : html`<a href="${item.href}">${item.label}</a>`;
}

/** Evidence as one cell: the links, separated the way the rest of the page is. */
function evidence(items: readonly StageEvidence[]): Safe {
  if (items.length === 0) return html`<span class="dim">none</span>`;
  return html`${items.map((item, index) =>
    index === 0 ? evidenceLink(item) : html` · ${evidenceLink(item)}`,
  )}`;
}

/** One stage's row: the name, its light, what the sweep saw, the rule, the record. */
function stageRow(stage: Stage): Safe {
  return html`<tr>
              <td>${stage.stage}</td>
              <td><span class="badge ${BADGE_CLASS[stage.state]}">${stage.state}</span></td>
              <td>${stage.last}</td>
              <td class="prose">${stage.rule}</td>
              <td class="prose">${evidence(stage.evidence)}</td>
            </tr>`;
}

/** A count and its noun: `1 unsealed event`, `3 unsealed events`. */
function plural(count: number, singular: string): string {
  return count === 1 ? `${count} ${singular}` : `${count} ${singular}s`;
}

/** One counter tile: the label, the number, the line under it. */
function counter(label: string, value: Safe, note: Safe): Safe {
  return html`<div class="counter">
        <div class="counter-label">${label}</div>
        <div class="counter-value">${value}</div>
        ${note}
      </div>`;
}

/**
 * The four counters, in the artboard's order.
 *
 * Every number is `statusCounters`' own; the page prints them and joins them
 * with separators. The two colours are readings of the stages below rather than
 * a second judgement — the sweep tile takes the sweep timer's light, the head
 * tile goes amber only while an event is unsealed — so the tiles and the table
 * can never disagree about whether something is wrong.
 */
function counters(c: Counter, sweepDegraded: boolean): Safe {
  const sweepNote =
    c.lastSweepAt === null
      ? html`<div class="counter-note">
          the sweep has not run on this environment
        </div>`
      : html`<div class="counter-note${sweepDegraded ? " warn" : ""}">
          ${fmtTimeUtc(c.lastSweepAt)} · ${c.lastSweepTrigger ?? "unknown"} ·
          every ${SWEEP_INTERVAL_MINUTES} min
        </div>`;

  const degraded = c.stagesFailing > 0 || c.stagesAttention > 0;
  const stagesNote = degraded
    ? [
        ...(c.stagesFailing > 0 ? [`${c.stagesFailing} failing`] : []),
        ...(c.stagesAttention > 0 ? [`${c.stagesAttention} attention`] : []),
      ].join(" · ")
    : "all ok";

  const headNote =
    c.newestSealSeq === null
      ? html`<div class="counter-note">no seal yet</div>`
      : html`<div class="counter-note${c.unsealedEvents > 0 ? " warn" : ""}">
          seal ${c.newestSealSeq} · ${plural(c.unsealedEvents, "unsealed event")}
        </div>`;

  return html`<div class="counters">
        ${counter("last sweep", html`${c.lastSweepAge ?? "never"}`, sweepNote)}
        ${counter(
          "stages",
          html`<span class="${degraded ? "danger" : "accent"}">${c.stagesOk}</span> / ${c.stagesTotal}`,
          html`<div class="counter-note ${degraded ? "danger" : "accent"}">
            ${stagesNote}
          </div>`,
        )}
        ${counter(
          "sealed head",
          html`${c.sealedHead === null ? "—" : c.sealedHead}`,
          headNote,
        )}
        ${counter(
          "witnessed",
          html`${c.witnessedSeals} / ${c.seals}`,
          html`<div class="counter-note">seals · ${c.witnessKind}</div>`,
        )}
      </div>`;
}

/**
 * The band above the counters, drawn only when a stage is failing or needs
 * attention.
 *
 * One line saying how many, and one sentence naming which. The names are the
 * rules module's own stage names rather than a paraphrase, so a reader who reads
 * the band and then the table is reading the same twelve words twice.
 */
function band(data: StatusData): Safe | null {
  const failing = data.stages
    .filter((stage) => stage.state === "failing")
    .map((stage) => stage.stage);
  const attention = data.stages
    .filter((stage) => stage.state === "attention")
    .map((stage) => stage.stage);
  if (failing.length === 0 && attention.length === 0) return null;

  const attentionPhrase = `${attention.length} ${
    attention.length === 1 ? "stage needs" : "stages need"
  } attention`;
  const failingPhrase =
    attention.length === 0
      ? `${failing.length} ${failing.length === 1 ? "stage is" : "stages are"} failing`
      : `${failing.length} ${failing.length === 1 ? "is" : "are"} failing`;
  const title =
    attention.length === 0
      ? failingPhrase
      : failing.length === 0
        ? attentionPhrase
        : `${attentionPhrase}, ${failingPhrase}`;

  const clauses = [
    ...(failing.length === 0
      ? []
      : [
          `${nameList(failing)} ${failing.length === 1 ? "is" : "are"} failing`,
        ]),
    ...(attention.length === 0
      ? []
      : [
          `${nameList(attention)} ${
            attention.length === 1 ? "needs" : "need"
          } attention`,
        ]),
  ];
  // Idle counts with ok, exactly as the fraction above does: a stage that is
  // owed nothing is not behind on anything.
  const holding = data.stages.filter(
    (stage) => stage.state === "ok" || stage.state === "idle",
  ).length;
  const rest =
    holding === 0
      ? ""
      : holding === 1
        ? " The other stage holds."
        : ` The other ${holding} stages hold.`;

  return html`<div class="alert">
        <span class="alert-title">${title}</span>
        <span class="prose">${sentenceCase(clauses.join("; "))}.${rest}</span>
      </div>`;
}

/** The exercised table: the stages that run only when someone asks. */
function exercised(data: StatusData): Safe {
  return html`<div class="table-wrap">
            <table class="dense">
              <thead>
                <tr>
                  <th>stage</th>
                  <th>last exercised</th>
                  <th>evidence</th>
                </tr>
              </thead>
              <tbody>
                ${data.exercised.map(
                  (each) => html`<tr>
                    <td>${each.stage}</td>
                    <td>${each.last}</td>
                    <td class="prose">${evidence(each.evidence)}</td>
                  </tr>`,
                )}
              </tbody>
            </table>
          </div>`;
}

/** A non-breaking space, for the legend's badges and the words between them. */
const NBSP = raw("&nbsp;");

export function renderStatus(ctx: PageContext, data: StatusData): string {
  const asOf =
    data.asOf === null
      ? html`no sweep has run on this environment yet`
      : html`as of the sweep run at ${fmtDate(data.asOf)} ${fmtTimeUtc(data.asOf)}`;
  const sweepDegraded = data.stages.some(
    (stage) => stage.stage === "sweep timer" && stage.state !== "ok",
  );
  const alert = band(data);

  return layout(ctx, {
    title: "Status",
    description:
      "Every stage of the pipeline, as the last sweep left it: a published rule applied to the log and to the sweep's stored report.",
    body: html`
      <div class="page-head">
        <h1>Status</h1>
        <span class="note"
          >${asOf} · <a href="/status" class="mono">GET /status</a> answers this
          table as JSON</span
        >
      </div>
      <p class="lede">
        Every stage of the pipeline, as the last sweep left it. Nothing here is
        probed when the page loads: each light is a published rule applied to the
        log and to the sweep's stored report, so the page says what the record
        says and cannot be warmed into looking better than it is.
      </p>

      ${alert ?? raw("")} ${counters(data.counters, sweepDegraded)}

      <section class="panel">
        <div class="table-wrap">
          <table class="dense">
            <caption>
              Pipeline, stage by stage
            </caption>
            <thead>
              <tr>
                <th>stage</th>
                <th>state</th>
                <th>last</th>
                <th>rule</th>
                <th>evidence</th>
              </tr>
            </thead>
            <tbody>
              ${data.stages.map(stageRow)}
            </tbody>
          </table>
        </div>
      </section>

      <div class="cols">
        <section class="panel">
          <h2 class="panel-title">Exercised, not probed</h2>
          <div class="panel-body">
            <p class="prose">
              Some stages run only when someone asks. They carry no light; the
              page shows when the log last saw them work.
            </p>
            ${exercised(data)}
          </div>
        </section>
        <section class="panel">
          <h2 class="panel-title">How a light is decided</h2>
          <div class="panel-body">
            <p class="prose">
              <span class="badge s-verified">ok</span>${NBSP} the rule holds as
              of the last sweep. ${NBSP}<span class="badge b-stale">attention</span
              >${NBSP} the rule failed once, or a step was skipped with a named
              reason, and the next run may clear it. ${NBSP}<span
                class="badge s-rejected"
                >failing</span
              >${NBSP} the rule has failed for longer than
              STATUS_FAILING_AFTER_MINUTES. ${NBSP}<span class="badge s-other"
                >idle</span
              >${NBSP} nothing for the step to do yet, which is not a failure.
            </p>
            <p class="prose">
              The thresholds are policy and show on the
              <a href="/policy">policy page</a>. The sweep writes its report per
              step after every run; this page reads that report and the log,
              never the network.
            </p>
            <pre class="block">curl -s ${ctx.origin}/status | jq '.stages[] | select(.state != "ok")'</pre>
          </div>
        </section>
      </div>
    `,
  });
}

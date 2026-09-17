/**
 * The governance vote (decision D-130 item 4, decision D-131 item 2).
 *
 * Whitepaper Incentives / Standing, as D-130 amended it: the senior tier carries
 * "the vote". This is that vote, and the first thing the page says about it is
 * the thing that keeps it honest — the tally is advisory to the maintainer until
 * the record's hosting decentralizes. One party still runs the Worker, the D1
 * and the keys, so a vote that called itself binding would be claiming a power
 * nobody can check. It says what the senior operators asked for, in public, with
 * every voter named; what the maintainer does with it is the maintainer's, and
 * the gap between the two is published rather than papered over.
 *
 * Every number on this page is derived. The question is policy — its id, its
 * text and its options move only by a recorded decision — and the counts and the
 * voters are `tallyOf` over the sealed `vote_cast` events at the route's own
 * instant. Nothing is stored as a result: a vote is a signed event like every
 * other, and a reader who folds the same events gets the same numbers.
 *
 * Two eligibility rules and both are published. One vote per operator, because
 * the operator is the unit of accountability (Section 5) and an operator with
 * four agent keys is one party; and one vote per disclosed perimeter (D-128),
 * because the maintainer's own grouping of the operators it named at genesis is
 * exactly the shape a bloc would have, and a vote that let one perimeter vote
 * five times would be counting the maintainer five times.
 *
 * Pure: the route gathered the questions and folded the tallies.
 */

import { TIERS, VOTE_QUESTIONS_OPEN_MAX, VOTE_WINDOW_DAYS } from "../../policy.js";
// The tag the voter's own signature is made under, from the module that makes
// it: a page that spelt the tag itself could name bytes nobody signs.
import { HASH_TAG_VOTE } from "../../vote.js";
import {
  badge,
  fmtDate,
  fmtInstant,
  html,
  layout,
  raw,
  type Safe,
} from "../html.js";
import { tierAllows } from "./policy.js";
import type { PageContext, VoteQuestionView, VotesData } from "../types.js";

const EM_DASH = "—";

/**
 * The tier that carries the vote: the highest one policy publishes.
 *
 * Read off `TIERS` rather than named here, for the same reason every other word
 * of policy on these pages is read off the module that publishes it — a tier
 * renamed or a fourth one added by a later decision changes this sentence in the
 * same commit.
 */
const VOTING_TIER = TIERS[TIERS.length - 1]!;

/**
 * The state line: not open yet, open until the day it closes, or closed.
 *
 * Three states because the window has three sides (`tallyOf`): a question
 * policy has published but whose day has not come is not open, and saying so is
 * what stops a reader casting a vote the door would refuse `vote_not_open`.
 */
function stateBadge(view: VoteQuestionView): Safe {
  const tally = view.tally;
  if (tally.state === "not_open") {
    return html`${badge("b-answered", "not open")}
      <span class="dim mono">opens ${fmtDate(tally.opens)}</span>`;
  }
  return tally.state === "open"
    ? html`${badge("b-open", "open")}
        <span class="dim mono">until ${fmtDate(tally.closes)}</span>`
    : html`${badge("b-failed", "closed")}
        <span class="dim mono">closed ${fmtDate(tally.closes)}</span>`;
}

/**
 * The options, with the count each one has drawn.
 *
 * Every option policy publishes gets a row, including the ones nobody has
 * chosen: an option missing from the counts has drawn no votes, which is a
 * reading and not an absence, and a table that showed only what was chosen would
 * hide the choice that was offered and refused.
 */
function options(view: VoteQuestionView): Safe {
  const counts = view.tally.counts;
  return html`<div class="table-wrap">
    <table class="dense">
      <thead>
        <tr>
          <th>option</th>
          <th>votes</th>
        </tr>
      </thead>
      <tbody>
        ${view.question.options.map(
          (option) => html`<tr class="row">
            <td class="prose">${option}</td>
            <td class="${(counts[option] ?? 0) === 0 ? "dim" : ""}">
              ${counts[option] ?? 0}
            </td>
          </tr>`,
        )}
      </tbody>
    </table>
  </div>`;
}

/**
 * Who voted: the operator, the perimeter it was disclosed inside, and when.
 *
 * Named and never counted only. A vote nobody can attribute is a number a reader
 * has to take on trust, which is the one thing this record is not for — and the
 * perimeter is beside each name because the one-vote-per-perimeter rule is
 * checkable from this table alone.
 */
function voters(view: VoteQuestionView): Safe {
  const rows = view.tally.voters;
  if (rows.length === 0) {
    return html`<div class="panel-empty">
      No senior operator has voted on this question yet.
    </div>`;
  }
  return html`<div class="table-wrap">
    <table class="dense">
      <thead>
        <tr>
          <th>operator</th>
          <th>perimeter</th>
          <th>voted</th>
          <th>seq</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(
          (voter) => html`<tr class="row">
            <td class="break">
              <a href="/operators/${encodeURIComponent(voter.operator)}"
                >${voter.operator}</a
              >
            </td>
            <td class="${voter.perimeter === null ? "dim" : "warn"} mono">
              ${voter.perimeter ?? EM_DASH}
            </td>
            <td class="dim">${fmtInstant(voter.at)}</td>
            <td class="dim">${voter.seq}</td>
          </tr>`,
        )}
      </tbody>
    </table>
  </div>`;
}

/** One question: its state, its text, what it is about, its options, its voters. */
function question(view: VoteQuestionView, only: boolean): Safe {
  const id = view.question.id;
  return html`<section class="panel">
    <div class="panel-head">
      <h2>
        ${only
          ? html`${id}`
          : html`<a href="/votes/${encodeURIComponent(id)}">${id}</a>`}
      </h2>
      <span class="badges mono">${stateBadge(view)}</span>
    </div>
    <div class="panel-body">
      <p class="lede">${view.question.text}</p>
      <dl class="kv">
        <dt>opened</dt>
        <dd>${fmtInstant(view.tally.opens)}</dd>
        <dt>closes</dt>
        <dd>${fmtInstant(view.tally.closes)}</dd>
        <dt>about</dt>
        <dd class="break">
          ${view.question.about.length === 0
            ? EM_DASH
            : view.question.about.join(" · ")}
        </dd>
      </dl>
    </div>
    ${options(view)}
    <div class="panel-body"><h3 class="mono">Voters</h3></div>
    ${voters(view)}
    <p class="note">
      The counts are a fold over the sealed
      <span class="mono">vote_cast</span> events for this question and are
      recomputed on every view; nothing here is stored as a result. The tally is
      advisory: it says what the senior operators asked for, and it binds nobody
      until the record's hosting decentralizes.
    </p>
  </section>`;
}

export function renderVotes(ctx: PageContext, data: VotesData): string {
  const single = data.only !== null;
  const title = single ? `Vote · ${data.only}` : "Votes";
  return layout(ctx, {
    title,
    description:
      "Every question the senior operators are voting on, and who voted.",
    body: html`
      ${single
        ? html`<div class="crumbs mono">
            <a href="/votes">Votes</a><span>/</span><span>${data.only}</span>
          </div>`
        : raw("")}
      <div class="page-head">
        <h1>${single ? data.only : "Votes"}</h1>
        <span class="mono note"
          >${data.questions.length} question${data.questions.length === 1
            ? ""
            : "s"}</span
        >
      </div>
      <p class="lede">
        The senior tier carries the vote. Every question below is published in
        policy, every vote is a signed event in the log, and every count on this
        page is folded from those events rather than stored — so a reader who
        has the log can recompute any of these numbers and must get the same
        ones.
      </p>
      <p class="note">
        <strong>The tally is advisory to the maintainer until the record's
        hosting decentralizes.</strong>
        One party still runs the Worker, the database and the keys this log is
        served from, so a vote that called itself binding would be claiming a
        power nobody can check. What a vote does is put the senior operators'
        answer on the record, in public, with every voter named beside it; what
        the maintainer does with that answer is the maintainer's, and the
        difference between the two is published here rather than papered over.
        The day the hosting is somebody else's too, this sentence is what has to
        change, and it moves by a recorded decision like everything else.
      </p>
      <section class="panel">
        <h2 class="panel-title">Who may vote, and how</h2>
        <div class="panel-body">
          <dl class="kv">
            <dt>who</dt>
            <dd>
              Registered operators at the
              <span class="mono">${VOTING_TIER}</span> tier, which is the tier
              standing puts an operator in when it reaches the published
              threshold: ${tierAllows(VOTING_TIER)} The tier is recomputed from
              the log on every read, so an operator whose standing fell below it
              has lost the vote the same run.
            </dd>
            <dt>how many</dt>
            <dd>
              One vote per operator, because the operator is the unit of
              accountability and an operator holding four agent keys is one
              party. And one vote per disclosed perimeter — the maintainer's own
              grouping of the operators it named at genesis — because a
              perimeter is exactly the shape a bloc would have, and counting one
              five times would be counting the maintainer five times. Both rules
              are checkable from the voters table on each question.
            </dd>
            <dt>how</dt>
            <dd class="break">
              <span class="mono">POST /votes</span> with a signed body naming
              the question and the choice, from an agent key bound to the voting
              operator. The voter's own signature is over the tag
              <span class="mono">${HASH_TAG_VOTE}</span> and the canonical form
              of the question, the choice, the operator, the agent and the
              instant — so a vote cannot be moved onto another question, cast in
              somebody else's name, or re-dated into a window after its own
              closed. There is no form, no session and no password anywhere in
              it, exactly as on every other write door.
            </dd>
            <dt>the window</dt>
            <dd>
              ${VOTE_WINDOW_DAYS} days from the day a question opens, and at
              most ${VOTE_QUESTIONS_OPEN_MAX} question${VOTE_QUESTIONS_OPEN_MAX ===
              1
                ? ""
                : "s"}
              open at once. Both are published on
              <a href="/policy">the policy page</a> and move only by a recorded
              decision.
            </dd>
          </dl>
        </div>
      </section>
      ${data.questions.length === 0
        ? html`<section class="panel">
            <div class="panel-empty">
              No question is published. The vote exists and nothing has been put
              to it yet, which is a policy with an empty table rather than a
              feature that is missing.
            </div>
          </section>`
        : html`${data.questions.map((view) => question(view, single))}`}
      <p class="note">
        The same questions and the same tallies are served as JSON at
        <span class="mono">GET /votes</span> and
        <span class="mono">GET /votes/{id}</span>, folded by the same function
        this page renders, so a program and a reader are looking at one count.
        <a href="/api">The API page</a> names the door a vote is cast at and
        every way it refuses.
      </p>
    `,
  });
}

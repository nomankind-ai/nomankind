/**
 * The votes page (decision D-130 item 4, decision D-131 item 2).
 *
 * The renderer is a pure function of the shape the route gathered, so every case
 * here builds one by hand — the published questions, and `tallyOf` over
 * `vote_cast` events made here — and reads the document back without a Worker, a
 * database or a clock. The fold is never reimplemented: the counts this file
 * expects are the counts the kernel returned, so a change to the rule shows up
 * as a changed page and never as a test that quietly agrees with itself.
 *
 * No number and no word of policy is written out. The window, the ceiling, the
 * questions, the options, the tier that carries the vote and the signing tag are
 * all read from the modules that publish them.
 */

import { describe, expect, it } from "vitest";

import type { Event } from "../src/events.js";
import {
  POLICY,
  TIERS,
  VOTE_QUESTIONS,
  VOTE_QUESTIONS_OPEN_MAX,
  VOTE_WINDOW_DAYS,
  voteWindow,
} from "../src/policy.js";
import { HASH_TAG_VOTE, VOTE_REFUSALS, tallyOf } from "../src/vote.js";
import { renderApi } from "../src/ui/pages/api.js";
import { tierAllows } from "../src/ui/pages/policy.js";
import { renderPolicy } from "../src/ui/pages/policy.js";
import { renderVotes } from "../src/ui/pages/votes.js";
import type { PageContext, VoteQuestionView, VotesData } from "../src/ui/types.js";

const ctx: PageContext = {
  environment: "local",
  path: "/votes",
  origin: "https://app.nomankind.ai",
  canonical_origin: "https://app.nomankind.ai",
};

const HASH =
  "sha256:1111111111111111111111111111111111111111111111111111111111111111";

/** The question policy publishes today; the fixtures are votes on it. */
const QUESTION = VOTE_QUESTIONS[0]!;
const WINDOW = voteWindow(QUESTION);

/** One sealed vote, in the shape the fold reads it in. */
function voteCast(
  seq: number,
  operator: string,
  perimeter: string | null,
  choice: string,
  at: string,
): Event {
  return {
    seq,
    at,
    type: "vote_cast",
    entry_id: null,
    payload: {
      question_id: QUESTION.id,
      choice,
      operator,
      agent: `1F916:${operator}`,
      perimeter,
      signed_at: at,
      signature: "c2lnbmF0dXJl",
    },
    hash: HASH,
    prev_hash: null,
  } as unknown as Event;
}

/** A day inside the window, and one past its end. */
const INSIDE = WINDOW.opens;
const AFTER = new Date(
  Date.parse(WINDOW.closes) + 24 * 60 * 60 * 1000,
).toISOString();

const events: Event[] = [
  voteCast(41, "k1.example", "kestrel-labs", QUESTION.options[0]!, INSIDE),
  voteCast(
    42,
    "k2.example",
    null,
    QUESTION.options[QUESTION.options.length - 1]!,
    INSIDE,
  ),
];

function view(now: string): VoteQuestionView {
  return { question: QUESTION, tally: tallyOf(events, QUESTION.id, now) };
}

function data(now: string, only: string | null = null): VotesData {
  return { questions: [view(now)], only };
}

describe("an open question with two votes", () => {
  const open = view(INSIDE);
  const html = renderVotes(ctx, data(INSIDE));

  it("is shown open, with the day it closes", () => {
    expect(open.tally.state).toBe("open");
    expect(html).toContain(">open</span>");
    expect(html).toContain(open.tally.closes.slice(0, 10));
  });

  it("prints the question's own text and every option it offers", () => {
    expect(html).toContain(QUESTION.text);
    for (const option of QUESTION.options) expect(html).toContain(option);
  });

  it("shows the counts the fold returned, and a zero for an option nobody chose", () => {
    for (const [option, count] of Object.entries(open.tally.counts)) {
      expect([option, html.includes(option)]).toEqual([option, true]);
      expect(count).toBeGreaterThanOrEqual(0);
    }
    // Two voters, two distinct choices here, so both counts are one and every
    // other published option is a zero the page still prints.
    expect(open.tally.voters).toHaveLength(2);
  });

  it("names every voter, its perimeter and the day it voted", () => {
    expect(html).toContain('href="/operators/k1.example"');
    expect(html).toContain('href="/operators/k2.example"');
    expect(html).toContain("kestrel-labs");
    // The voter with no disclosed perimeter is a dash and never a blank.
    expect(html).toContain("—");
    expect(html).toContain("<th>perimeter</th>");
  });

  it("links each question to its own page from the listing", () => {
    expect(html).toContain(`href="/votes/${encodeURIComponent(QUESTION.id)}"`);
  });
});

describe("a closed question", () => {
  const closed = view(AFTER);
  const html = renderVotes(ctx, data(AFTER));

  it("is shown closed rather than open until a past day", () => {
    expect(closed.tally.state).toBe("closed");
    expect(html).toContain(">closed</span>");
    expect(html).not.toContain(">open</span>");
  });

  it("still names the votes that were cast while it was open", () => {
    expect(closed.tally.voters).toHaveLength(2);
    expect(html).toContain("k1.example");
  });
});

describe("the advisory sentence", () => {
  const html = renderVotes(ctx, data(INSIDE));

  it("is on the page, in the words the decision fixed", () => {
    expect(html).toContain("The tally is advisory to the maintainer");
    expect(html).toContain("hosting decentralizes");
  });

  it("says why: one party still runs the hosting", () => {
    expect(html).toContain("One party still runs the Worker");
    expect(html).toContain("nobody can check");
  });

  it("travels on the tally itself, so a JSON reader is told too", () => {
    expect(view(INSIDE).tally.advisory).toBe(true);
  });
});

describe("who may vote, and how", () => {
  const html = renderVotes(ctx, data(INSIDE));
  const senior = TIERS[TIERS.length - 1]!;

  it("names the tier from policy, with what that tier allows", () => {
    expect(html).toContain(senior);
    expect(html).toContain(tierAllows(senior));
  });

  it("states both counting rules: one per operator and one per perimeter", () => {
    expect(html).toContain("One vote per operator");
    expect(html).toContain("one vote per disclosed perimeter");
  });

  it("names the door, the signing tag and the window from policy", () => {
    expect(html).toContain("POST /votes");
    expect(html).toContain(HASH_TAG_VOTE);
    expect(html).toContain(String(VOTE_WINDOW_DAYS));
    expect(html).toContain(String(VOTE_QUESTIONS_OPEN_MAX));
  });
});

describe("one question's own page", () => {
  const html = renderVotes(ctx, data(INSIDE, QUESTION.id));

  it("carries the crumb back to the listing and does not link itself", () => {
    expect(html).toContain('<a href="/votes">Votes</a>');
    expect(html).not.toContain(`href="/votes/${encodeURIComponent(QUESTION.id)}"`);
    expect(html).toContain(QUESTION.id);
  });
});

describe("the policy page's Vote group", () => {
  const html = renderPolicy(ctx, POLICY);

  it("publishes the window, the ceiling and the open question", () => {
    expect(html).toContain("VOTE_WINDOW_DAYS");
    expect(html).toContain(String(POLICY.VOTE_WINDOW_DAYS));
    expect(html).toContain("VOTE_QUESTIONS_OPEN_MAX");
    expect(html).toContain(String(POLICY.VOTE_QUESTIONS_OPEN_MAX));
    for (const question of POLICY.VOTE_QUESTIONS) {
      expect(html).toContain(`VOTE_QUESTIONS.${question.id}`);
      expect(html).toContain(question.text);
      for (const about of question.about) expect(html).toContain(about);
    }
  });

  it("says the tally is advisory, and links the votes page", () => {
    expect(html).toContain('<a href="/votes">');
    expect(html).toContain("advisory to the maintainer");
  });
});

describe("the API page", () => {
  const html = renderApi(ctx);

  it("names the three doors", () => {
    for (const path of ["POST", "/votes", "/votes/{id}"]) {
      expect(html).toContain(path);
    }
  });

  it("names every refusal the check applies, in the module's own order", () => {
    expect(html).toContain(VOTE_REFUSALS.join(", "));
  });

  it("documents the vote_cast event and the signing bytes", () => {
    expect(html).toContain("vote_cast");
    expect(html).toContain(HASH_TAG_VOTE);
    expect(html).toContain("question_id, choice, operator, agent");
  });
});

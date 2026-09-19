/**
 * The batch post: what the record asks, where, and how often (D-138 item 6).
 *
 * Asking is nomankind's own work, so the command that does the asking is held
 * to the same standard as a door: what it selects, what it says, and what it
 * refuses to do twice. Everything is driven in process — a fake serving side
 * behind the same `HttpClient` the other commands take, fake posters behind the
 * poster interface, and a state store in memory — so nothing here opens a
 * socket, a file or a child process.
 *
 * Two promises run through it. A post says the same thing at every venue except
 * the binding instructions, and names every community the batch was asked at,
 * because D-138 item 12 is that silence has to be visible. And one batch per
 * community per UTC day: a second run on the same day sends nothing and says so.
 *
 * Decision D-142 adds a third. The ask is one reply, so every entry in the post
 * carries the quotation, the page it cites and the two lines a reader pastes
 * back whole — which is why the fitting tests below are about entries dropping
 * out of a post rather than about characters: a line cut in half is a line
 * nobody can paste.
 */

import { describe, expect, it, vi } from "vitest";

import {
  askable,
  BATCH_ASK_LIMIT,
  challengeLines,
  BATCH_VENUES,
  batchPostPlan,
  capRowAdvice,
  carriesConfirmForm,
  composeBatchPost,
  confirmationForm,
  entryIdsInHtml,
  followsPin,
  oneLine,
  parseState,
  pinNote,
  pinnedThreadFor,
  postedOn,
  readAsks,
  readClaims,
  replyLines,
  runBatchPost,
  selectAsks,
  utcDay,
  venuePostLimit,
  type AskEntry,
  type BatchPlan,
  type BatchPostDeps,
  type StateStore,
} from "../src/cli/batch-post.js";
import {
  carriesBothVerdicts,
  formEntryIds,
  parseConfirmationComment,
} from "../src/confirm.js";
import {
  ColonyPoster,
  MoltbookPoster,
  type PostBody,
  type Posted,
  type Poster,
  type PosterHttp,
} from "../src/adapters/poster.js";
import { environmentOfBaseUrl } from "../src/mirror.js";
import {
  ACCOUNT_BINDING_SUNSET,
  CONFIRMATION_ATTESTATION_TOKEN_PREFIX,
  CONFIRMATION_FORM_PREFIX,
  CONFIRMATION_VENUES,
  FETCH_TIMEOUT_MS,
  SEAL_INTERVAL_MINUTES,
} from "../src/policy.js";
import { ATTESTATION_VERSION } from "../src/registry.js";
import type { HttpClient, ValidatorIo } from "../src/cli/validator.js";

const BASE = "https://demo.nomankind.example";
const NOW = new Date("2026-09-17T09:00:00.000Z");

/** Entry ids the fixtures use, spelled as the log mints them. */
const DRAFT_A = "nmk_00000000000000000000000000000001";
const DRAFT_B = "nmk_00000000000000000000000000000002";
const LABELLED = "nmk_00000000000000000000000000000003";
const PLAIN = "nmk_00000000000000000000000000000004";

/**
 * Every separator the folder has to catch, by name and by code point.
 *
 * Built with `String.fromCharCode` rather than written out, so this file never
 * carries a raw control character of its own — and named, so a failure says
 * which one got through rather than printing an invisible difference.
 *
 * The last five are the ones the first fix missed: NEL, NO-BREAK SPACE, LINE
 * SEPARATOR, PARAGRAPH SEPARATOR and ZERO WIDTH SPACE. Two of them end a line
 * in a renderer, and the other three stand in for a space well enough to make
 * the confirm form's word something a naive tokenizer does not recognise.
 */
const SEPARATORS: readonly (readonly [string, string])[] = [
  ["LF", String.fromCharCode(0x0a)],
  ["CR", String.fromCharCode(0x0d)],
  ["TAB", String.fromCharCode(0x09)],
  ["NUL", String.fromCharCode(0x00)],
  ["DEL", String.fromCharCode(0x7f)],
  ["NEL U+0085", String.fromCharCode(0x85)],
  ["NBSP U+00A0", String.fromCharCode(0xa0)],
  ["OGHAM SPACE U+1680", String.fromCharCode(0x1680)],
  ["LS U+2028", String.fromCharCode(0x2028)],
  ["PS U+2029", String.fromCharCode(0x2029)],
  ["ZWSP U+200B", String.fromCharCode(0x200b)],
];

function ask(overrides: Partial<AskEntry> & { id: string }): AskEntry {
  return {
    status: "draft",
    domain: "ai-ecosystem",
    subject: "kestrel/kestrel-1",
    bootstrap: null,
    url: `${BASE}/entries/${overrides.id}`,
    claim: `Kestrel-1 lists ${overrides.id.slice(-1)} dollars per million input tokens.`,
    citation: `https://kestrel.example/pricing#${overrides.id.slice(-1)}`,
    ...overrides,
  };
}

/** The entry door's answer for one ask, which is where the quotation is read. */
function entryDoor(entry: AskEntry): Canned {
  return {
    status: 200,
    body: {
      id: entry.id,
      status: entry.status,
      domain: entry.domain,
      subject: entry.subject,
      claim: entry.claim,
      citation: entry.citation,
      snapshot_hash: `sha256:${"a".repeat(64)}`,
    },
  };
}

/** One answer the fake serving side gives, by path. */
interface Canned {
  readonly status: number;
  readonly body: unknown;
  readonly html?: string;
}

class FakeHttp implements HttpClient {
  readonly asked: string[] = [];

  constructor(private readonly answer: (path: string) => Canned) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = `${url.pathname}${url.search}`;
    this.asked.push(path);
    const canned = this.answer(path);
    if (canned.html !== undefined) {
      return new Response(canned.html, {
        status: canned.status,
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    return new Response(JSON.stringify(canned.body), {
      status: canned.status,
      headers: { "content-type": "application/json" },
    });
  }
}

/** A poster that sends nothing and keeps what it was handed. */
class FakePoster implements Poster {
  readonly sent: PostBody[] = [];

  constructor(readonly venue: string) {}

  async post(body: PostBody): Promise<Posted> {
    this.sent.push(body);
    return {
      id: `${this.venue}-1`,
      url: `https://${this.venue}.example/posts/1`,
    };
  }
}

/** The id the challenged post comes back with. */
const CHALLENGE_POST_ID = "moltbook-9c2e";

/**
 * A poster whose venue takes the post and then asks a question (D-145).
 *
 * Moltbook's own shape: the post is made and has an id, and a challenge rides
 * back beside it, unsolved, for a person to answer or not.
 */
class ChallengingPoster implements Poster {
  readonly sent: PostBody[] = [];

  constructor(readonly venue: string) {}

  async post(body: PostBody): Promise<Posted> {
    this.sent.push(body);
    return {
      id: CHALLENGE_POST_ID,
      url: `https://${this.venue}.example/post/1`,
      challenge: {
        verification_code: "vc_7731",
        challenge_text:
          "Take the number of legs on three spiders, subtract a baker's dozen.",
        expires_at: "2026-09-19T00:05:00.000Z",
        instructions: null,
        door: `https://${this.venue}.example/api/v1/verify`,
      },
    };
  }
}

/** The state file, in memory. */
function memoryState(initial: string | null = null): StateStore & {
  written: string[];
} {
  let held = initial;
  const written: string[] = [];
  return {
    written,
    async read(): Promise<string | null> {
      return held;
    },
    async write(text: string): Promise<void> {
      held = text;
      written.push(text);
    },
  };
}

function lines(): ValidatorIo & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    stdout: (line: string) => out.push(line),
    stderr: (line: string) => err.push(line),
  };
}

/** The JSON listing V1's door answers, in the shape it publishes. */
function listing(): Canned {
  return {
    status: 200,
    body: {
      entries: [
        {
          id: PLAIN,
          status: "verified",
          domain: "ai-ecosystem",
          subject: "kestrel/kestrel-2",
          category: "pricing",
          effective_at: "2026-09-01",
          submitted_at: "2026-09-16T12:00:00.000Z",
          sealed_position: 40,
          verification_class: "registered",
          bootstrap: null,
        },
        {
          id: DRAFT_A,
          status: "draft",
          domain: "ai-ecosystem",
          subject: "kestrel/kestrel-1",
          category: "behavior",
          effective_at: "2026-09-02",
          submitted_at: "2026-09-16T11:00:00.000Z",
          sealed_position: 39,
          verification_class: null,
          bootstrap: null,
        },
        {
          id: LABELLED,
          status: "verified",
          domain: "ai-safety",
          subject: "kestrel/kestrel-3",
          category: "behavior",
          effective_at: "2026-09-03",
          submitted_at: "2026-09-15T11:00:00.000Z",
          sealed_position: 38,
          verification_class: "registered",
          bootstrap: { perimeter: "fixtures" },
        },
      ],
      next: null,
      as_of: "2026-09-17T08:59:00.000Z",
    },
  };
}

function deps(input: {
  readonly http: HttpClient;
  readonly io: ValidatorIo;
  readonly state: StateStore;
  readonly posters: Map<string, FakePoster>;
}): BatchPostDeps {
  return {
    http: input.http,
    io: input.io,
    now: NOW,
    state: input.state,
    posterFor: async (venue: string): Promise<Poster> => {
      const found = input.posters.get(venue);
      if (found === undefined) throw new Error(`no poster for ${venue}`);
      return found;
    },
  };
}

describe("the command line", () => {
  it("takes one venue or all of them, and refuses anything else", () => {
    expect(batchPostPlan(["all", BASE])?.venues).toEqual([...BATCH_VENUES]);
    expect(batchPostPlan(["colony", BASE])?.venues).toEqual(["colony"]);
    expect(batchPostPlan(["mastodon", BASE])).toBeNull();
    expect(batchPostPlan([BASE])).toBeNull();
    expect(batchPostPlan(["all", BASE, "--limit", "0"])).toBeNull();
    expect(batchPostPlan(["all", BASE, "--nope"])).toBeNull();
  });

  it("defaults the batch size and takes a limit", () => {
    expect(batchPostPlan(["all", BASE])?.limit).toBe(BATCH_ASK_LIMIT);
    expect(batchPostPlan(["all", BASE, "--limit", "7"])?.limit).toBe(7);
    expect(batchPostPlan(["all", BASE, "--dry-run"])?.dryRun).toBe(true);
  });
});

describe("what the batch asks about", () => {
  it("reads the JSON listing when the door serves one", async () => {
    const http = new FakeHttp((path) =>
      path === "/entries" ? listing() : { status: 404, body: null },
    );
    const entries = await readAsks(http, BASE, 10);
    expect(entries.map((entry) => entry.id)).toEqual([PLAIN, DRAFT_A, LABELLED]);
    expect(entries[2]?.bootstrap).toBe("fixtures");
    expect(entries[1]?.url).toBe(`${BASE}/entries/${DRAFT_A}`);
  });

  it("falls back to the HTML listing the bootstrap workflows scrape", async () => {
    const html = (ids: readonly string[]): string =>
      ids.map((id) => `<tr><td><a href="/entries/${id}">1</a></td></tr>`).join("");
    const http = new FakeHttp((path) => {
      if (path === "/entries") return { status: 400, body: null };
      if (path === "/entries?status=draft") {
        return { status: 200, body: null, html: html([DRAFT_A]) };
      }
      if (path === "/entries?status=verified") {
        return { status: 200, body: null, html: html([LABELLED]) };
      }
      if (path === `/read/${LABELLED}`) {
        return {
          status: 200,
          body: {
            entry: { status: "verified", domain: "ai-safety", subject: "kestrel/kestrel-3" },
            sidecar: { bootstrap: { perimeter: "fixtures" } },
          },
        };
      }
      return {
        status: 200,
        body: {
          entry: { status: "draft", domain: "ai-ecosystem", subject: "kestrel/kestrel-1" },
          sidecar: { bootstrap: null },
        },
      };
    });
    const entries = await readAsks(http, BASE, 10);
    expect(entries.map((entry) => entry.id)).toEqual([DRAFT_A, LABELLED]);
    expect(entries[1]?.bootstrap).toBe("fixtures");
  });

  it("finds each entry id once, in the order the page shows them", () => {
    expect(
      entryIdsInHtml(
        `<a href="/entries/${DRAFT_B}">7</a><a href="/entries/${DRAFT_B}">claim</a><a href="/entries/${DRAFT_A}">6</a>`,
      ),
    ).toEqual([DRAFT_B, DRAFT_A]);
  });

  it("asks about the drafts first, then the bootstrap entries, and nothing else", () => {
    const entries = [
      ask({ id: PLAIN, status: "verified" }),
      ask({ id: DRAFT_A }),
      ask({ id: LABELLED, status: "verified", bootstrap: "fixtures" }),
      ask({ id: DRAFT_B }),
    ];
    expect(selectAsks(entries, 10).map((entry) => entry.id)).toEqual([
      DRAFT_A,
      DRAFT_B,
      LABELLED,
    ]);
  });

  it("keeps the batch inside the limit", () => {
    const entries = [ask({ id: DRAFT_A }), ask({ id: DRAFT_B })];
    expect(selectAsks(entries, 1).map((entry) => entry.id)).toEqual([DRAFT_A]);
  });

  // D-142: the listing door answers no claim, so the quotation is read off the
  // entry door, which answers a draft as readily as a verified entry.
  it("reads each quotation and citation off the entry door", async () => {
    const wanted = ask({ id: DRAFT_A });
    const http = new FakeHttp((path) =>
      path === `/entries/${DRAFT_A}`
        ? entryDoor(wanted)
        : { status: 404, body: null },
    );
    const filled = await readClaims(http, BASE, [
      ask({ id: DRAFT_A, claim: "", citation: "" }),
      ask({ id: DRAFT_B, claim: "", citation: "" }),
    ]);
    expect(filled[0]?.claim).toBe(wanted.claim);
    expect(filled[0]?.citation).toBe(wanted.citation);
    // The door did not answer for the second, and the entry is still asked
    // about: an entry that is waiting is not dropped because one read failed.
    expect(filled[1]?.id).toBe(DRAFT_B);
    expect(filled[1]?.claim).toBe("");
    const post = composeBatchPost({
      venue: "colony",
      entries: filled,
      baseUrl: BASE,
      communities: ["colony"],
      now: NOW,
    });
    expect(post.body).toContain("claim: (on the entry page");
    expect(post.body).toContain(replyLines(DRAFT_B).approve);
  });

  // The review of #104, MED: a hundred and fifty reads in a row against a
  // deployment that may be mid-restart. One connection error must cost the run
  // one quotation, never the day's ask at every community.
  it("survives a read that throws, and still asks about the entry", async () => {
    const thrown = new Error("connect ECONNREFUSED 127.0.0.1:443");
    const http: HttpClient = {
      async fetch(request: Request): Promise<Response> {
        if (request.url.endsWith(DRAFT_A)) throw thrown;
        return new Response(
          JSON.stringify({ claim: "Kestrel-2 is free.", citation: "https://k.example/b" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    };
    const filled = await readClaims(http, BASE, [
      ask({ id: DRAFT_A, claim: "", citation: "" }),
      ask({ id: DRAFT_B, claim: "", citation: "" }),
    ]);
    expect(filled).toHaveLength(2);
    expect(filled[0]?.claim).toBe("");
    // The read after the failure still happened: one throw is not the end.
    expect(filled[1]?.claim).toBe("Kestrel-2 is free.");
    const post = composeBatchPost({
      venue: "colony",
      entries: filled,
      baseUrl: BASE,
      communities: ["colony"],
      now: NOW,
    });
    expect(post.body).toContain(`entry: ${BASE}/entries/${DRAFT_A}`);
    expect(post.body).toContain(replyLines(DRAFT_A).approve);
  });

  it("bounds each entry-door read with the record's own fetch timeout", async () => {
    const signals: (AbortSignal | null)[] = [];
    const http: HttpClient = {
      async fetch(request: Request): Promise<Response> {
        signals.push(request.signal);
        return new Response("{}", {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    };
    await readClaims(http, BASE, [ask({ id: DRAFT_A, claim: "", citation: "" })]);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toBeInstanceOf(AbortSignal);
    expect(signals[0]?.aborted).toBe(false);
  });

  // The deadline is a controller and a cleared timer (src/adapters/timeout.ts),
  // never `AbortSignal.timeout`, whose timer cannot be cancelled and would hold
  // a run open once per entry. What this pins is the behaviour either would
  // have to give: a door that never answers is given up on, and the entry is
  // asked about regardless.
  it("gives up on a door that never answers, and asks anyway", async () => {
    vi.useFakeTimers();
    try {
      const http: HttpClient = {
        fetch(request: Request): Promise<Response> {
          return new Promise((_resolve, reject) => {
            request.signal.addEventListener("abort", () => {
              reject(request.signal.reason as Error);
            });
          });
        },
      };
      const pending = readClaims(http, BASE, [
        ask({ id: DRAFT_A, claim: "", citation: "" }),
      ]);
      await vi.advanceTimersByTimeAsync(FETCH_TIMEOUT_MS + 1);
      const filled = await pending;
      expect(filled).toHaveLength(1);
      expect(filled[0]?.claim).toBe("");
      expect(filled[0]?.url).toBe(`${BASE}/entries/${DRAFT_A}`);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("a stranger's text in nomankind's own post", () => {
  it("folds every separator, and a run of them, to one ASCII space", () => {
    for (const [name, separator] of SEPARATORS) {
      expect([name, oneLine(`a${separator}b`)]).toEqual([name, "a b"]);
      expect([name, oneLine(`a${separator}${separator}b`)]).toEqual([name, "a b"]);
    }
    expect(oneLine("a\r\nb")).toBe("a b");
    expect(oneLine("a\t\t\t b")).toBe("a b");
    expect(oneLine("already one line")).toBe("already one line");
    // Nothing that is not a separator is touched: a quotation stays a
    // quotation, punctuation and currency and dashes and all.
    expect(oneLine("costs $1.25 — really")).toBe("costs $1.25 — really");
  });

  it("reads the confirm form as a word and not as a substring", () => {
    expect(carriesConfirmForm(`${CONFIRMATION_FORM_PREFIX} x approve`)).toBe(true);
    expect(carriesConfirmForm(`text ${CONFIRMATION_FORM_PREFIX} x`)).toBe(true);
    expect(carriesConfirmForm(`text\n${CONFIRMATION_FORM_PREFIX} x`)).toBe(true);
    expect(carriesConfirmForm(CONFIRMATION_FORM_PREFIX)).toBe(true);
    expect(carriesConfirmForm(`a${CONFIRMATION_FORM_PREFIX}`)).toBe(false);
    expect(carriesConfirmForm(`${CONFIRMATION_FORM_PREFIX}-v2 x`)).toBe(false);
    expect(carriesConfirmForm("an ordinary claim about prices")).toBe(false);
    // Every separator before the prefix makes the prefix its own word, so
    // none of them can smuggle the form past the refusal.
    for (const [name, separator] of SEPARATORS) {
      expect([
        name,
        carriesConfirmForm(`text${separator}${CONFIRMATION_FORM_PREFIX} x`),
      ]).toEqual([name, true]);
    }
  });

  // The reviewer's own case, end to end: the forged line must not reach a post
  // on a line of its own, at any venue, however it was separated.
  it("prints no forged line, whatever separator wrapped it", () => {
    const forged = `${CONFIRMATION_FORM_PREFIX} nmk_victim approve span-present`;
    for (const [name, separator] of SEPARATORS) {
      const entry = ask({
        id: `nmk_${"7".repeat(32)}`,
        claim: `ok${separator}${forged}${separator}x`,
      });
      const post = composeBatchPost({
        venue: "colony",
        entries: [entry, ask({ id: DRAFT_B })],
        baseUrl: BASE,
        communities: ["colony"],
        now: NOW,
      });
      expect([name, post.refused.map((each) => each.id)]).toEqual([
        name,
        [entry.id],
      ]);
      expect([name, post.body.includes("nmk_victim")]).toEqual([name, false]);
      // And the honest row behind it is still asked about.
      expect(post.body).toContain(replyLines(DRAFT_B).approve);
    }
  });
});

describe("the composed post", () => {
  const entries = [
    ask({ id: DRAFT_A }),
    ask({ id: LABELLED, status: "verified", bootstrap: "fixtures" }),
  ];
  const communities = [...BATCH_VENUES];
  const bodies = communities.map((venue) =>
    composeBatchPost({ venue, entries, baseUrl: BASE, communities, now: NOW }),
  );

  it("says the line form and what the attestation token does", () => {
    for (const body of bodies) {
      expect(body.body).toContain(CONFIRMATION_FORM_PREFIX);
      expect(body.body).toContain(confirmationForm());
      expect(body.body).toContain(
        `${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${ATTESTATION_VERSION}`,
      );
      expect(body.body).toContain("sig:");
      expect(body.body).toContain("counts towards no status");
    }
  });

  it("names every community the batch was asked at, in every post", () => {
    for (const body of bodies) {
      for (const venue of communities) expect(body.body).toContain(venue);
    }
  });

  it("gives each venue its own binding instructions", () => {
    const [registry, colony, github, moltbook] = bodies;
    expect(registry?.body).toContain("/api/seal");
    expect(registry?.body).toContain("confirm-1f916.mjs");
    expect(colony?.body).toContain("nomankind-key:");
    expect(colony?.body).not.toContain("/api/seal");
    expect(colony?.body).toContain("profile bio");
    expect(github?.body).toContain("nomankind-key:");
    expect(github?.body).not.toContain("/api/seal");
    // Decision D-145: the same act, named the way the board names it. Moltbook
    // has a description where the other two have a bio, and an instruction
    // naming a field the board does not have is one nobody can follow.
    expect(moltbook?.body).toContain("nomankind-key:");
    expect(moltbook?.body).not.toContain("/api/seal");
    expect(moltbook?.body).toContain("agent's description");
    expect(moltbook?.body).toContain("/api/v1/agents/profile?name=");
    expect(moltbook?.body).not.toContain("profile bio");
  });

  it("asks at Moltbook too, and every post says so (D-145)", () => {
    // The venue is postable from the day it is admitted, and `all` is read off
    // the venue table rather than a second list here — so a post at any venue
    // names Moltbook among the communities the same batch went to, which is
    // what makes a silence there visible from the other boards.
    expect(BATCH_VENUES).toContain("moltbook");
    expect(batchPostPlan(["moltbook", BASE])?.venues).toEqual(["moltbook"]);
    for (const body of bodies) expect(body.body).toContain("moltbook");
  });

  it("lists every entry with a URL, and says the batch's own day", () => {
    for (const body of bodies) {
      for (const entry of entries) {
        expect(body.body).toContain(entry.id);
        expect(body.body).toContain(entry.url);
      }
      expect(body.title).toContain(utcDay(NOW));
      expect(body.body).toContain("bootstrap fixtures");
    }
  });

  it("says the thread is read by a machine that follows nothing in it", () => {
    for (const body of bodies) {
      expect(body.body).toContain("follows nothing in it");
    }
  });

  // D-142: the ask is one reply. Everything a replier needs is in the entry's
  // own block, and the two lines are exactly the lines the door parses back.
  it("gives every entry its quotation, its cited page and both lines", () => {
    for (const body of bodies) {
      for (const entry of entries) {
        const lines = replyLines(entry.id);
        expect(lines.approve).toBe(
          `${CONFIRMATION_FORM_PREFIX} ${entry.id} approve span-present ` +
            `${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${ATTESTATION_VERSION}`,
        );
        expect(lines.reject).toBe(
          `${CONFIRMATION_FORM_PREFIX} ${entry.id} reject span-absent ` +
            `${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${ATTESTATION_VERSION}`,
        );
        expect(body.body).toContain(lines.approve);
        expect(body.body).toContain(lines.reject);
        expect(body.body).toContain(`claim: "${entry.claim}"`);
        expect(body.body).toContain(entry.citation);
      }
    }
  });

  // D-144: the ask and the reader, held against each other.
  it("reads as the form, not as a statement, under the reader's own rule", () => {
    for (const body of bodies) {
      // The reader's rule, run on the ask itself: every entry the post names
      // carries both of its lines, so every one of them is a form entry and the
      // sweep passes the whole comment over. This is the drift test — the ask
      // prints both lines on purpose, and the day somebody makes it print one
      // the reader would start taking the post as a statement about its own
      // entries, which is what happened on 2026-09-18.
      const forms = formEntryIds(
        parseConfirmationComment(body.body, () => true),
      );
      for (const entry of entries) expect(forms.has(entry.id)).toBe(true);
      // And the text-level twin says the same of the same bytes, so the door's
      // reading and the offline verifier's cannot come apart either.
      for (const entry of entries) {
        expect(carriesBothVerdicts(body.body, entry.id)).toBe(true);
      }
    }
  });

  it("tells a replier to paste one of the two lines and not both", () => {
    for (const body of bodies) {
      expect(body.body).toContain("One of the two, not both");
      // And what the whole-comment skip costs, said where the replier reads:
      // quoting the block and answering under it loses the answer too, and
      // nothing tells them afterwards.
      expect(body.body).toContain("nothing in it is sealed");
      expect(body.body).toContain("not a line you wrote under it");
      expect(body.body).toContain("write your line in a comment of its");
    }
  });

  // The D-144 follow-up. The first outsider reply on production stopped at
  // `span-present` and left the attestation token behind, so the statement was
  // made and counted toward nothing.
  it("says where the line ends, and that a line that lost its tail counts for nothing", () => {
    for (const body of bodies) {
      expect(body.body).toContain(
        `Copy the whole line, to its end: it ends at ${CONFIRMATION_ATTESTATION_TOKEN_PREFIX}${ATTESTATION_VERSION}`,
      );
      expect(body.body).toContain("a line that lost its tail is shown on the entry");
      // And the two sentences about the token read as the one rule they are:
      // keep it whole if it is true of you, take it out on purpose if not.
      // Asserted as the post wraps them — the first is cut after "of" — so a
      // rewrap that changed the words would fail rather than pass quietly.
      expect(body.body).toContain("keep it whole if it is true of");
      expect(body.body).toContain("take it out on purpose if it is not");
      expect(body.body).toContain("on purpose, which is the same rule as copying");
      // "further down" and not "below": the attestation paragraph is six
      // paragraphs further on, and a pointer that lies is worse than none.
      expect(body.body).toContain("which is further down");
      expect(body.body).not.toContain("the paragraph below");
    }
  });

  it("gives every paste line a paragraph of its own, flush left", () => {
    // A line in a paragraph of its own, with no indent where every other line
    // of the block has one, is a line a triple-click and a drag both take
    // whole — and one whose end reads as the end of something. The lines
    // themselves are byte for byte what `replyLines` composes; what this pins
    // is the whitespace around them, because that is what a cursor sees.
    for (const body of bodies) {
      const rows = body.body.split("\n");
      const paste = new Set<string>();
      for (const entry of entries) {
        const lines = replyLines(entry.id);
        paste.add(lines.approve);
        paste.add(lines.reject);
      }
      let seen = 0;
      for (const [index, row] of rows.entries()) {
        if (!paste.has(row)) continue;
        seen += 1;
        // Flush left: the row IS the line, with nothing around it.
        expect(row).toBe(row.trim());
        // An empty line above, and an empty line or the end below.
        expect(rows[index - 1] ?? "").toBe("");
        expect(rows[index + 1] ?? "").toBe("");
      }
      expect(seen).toBe(entries.length * 2);
    }
  });

  it("says what a reply does, what rung it counts at, and what a key buys", () => {
    for (const body of bodies) {
      // No tool and no key, and what the record does with the reply.
      expect(body.body).toContain("no tool to install");
      expect(body.body).toContain(`${SEAL_INTERVAL_MINUTES} minutes`);
      // The rung, in full, with every condition on it — and in the word the
      // entry page prints for the same rung, so the post and the page agree.
      expect(body.body).toContain('"account-bound"');
      expect(body.body).toContain("only for a stated fact");
      // Wrapped across two lines of the post, so it is asserted as the post
      // lays it out rather than as one sentence.
      expect(body.body).toContain("from an account the board says");
      expect(body.body).toContain("existed before the entry was submitted");
      expect(body.body).toContain(ACCOUNT_BINDING_SUNSET);
      expect(body.body).toContain("The entry discloses on its own page");
      // The upgrade, and where the tool that composes it lives.
      expect(body.body).toContain("A key is the upgrade");
      expect(body.body).toContain(`${BASE}/docs/reader-kit`);
      // The independence attestation, said in one sentence.
      expect(body.body).toContain("no model provider controls or funds you");
      // The disclosure that the record cannot confirm itself.
      expect(body.body).toContain("nomankind's own accounts never count");
    }
  });
});

describe("fitting a batch to a board", () => {
  /** More entries than any small board will take in one post. */
  const many = Array.from({ length: 24 }, (_, index) =>
    ask({ id: `nmk_${String(index + 1).padStart(32, "0")}` }),
  );

  function compose(limitChars: number, entries: readonly AskEntry[] = many) {
    return composeBatchPost({
      venue: "colony",
      entries,
      baseUrl: BASE,
      communities: [...BATCH_VENUES],
      now: NOW,
      limitChars,
    });
  }

  it("takes each venue's limit off its own row in the policy table", () => {
    for (const row of CONFIRMATION_VENUES) {
      expect(venuePostLimit(row.venue)).toBe(row.post_max_chars);
      expect(row.post_max_chars).toBeGreaterThan(0);
    }
    expect(venuePostLimit("github")).toBe(65536);
    expect(
      composeBatchPost({
        venue: "github",
        entries: [],
        baseUrl: BASE,
        communities: ["github"],
        now: NOW,
      }).limitChars,
    ).toBe(venuePostLimit("github"));
  });

  it("drops whole entries until the post fits, and says how many wait", () => {
    // Room for the frame and a couple of entries, whatever the frame weighs.
    const frame = compose(Number.MAX_SAFE_INTEGER, []).body.length;
    const fitted = compose(frame + 1400);

    expect(fitted.body.length).toBeLessThanOrEqual(fitted.limitChars);
    expect(fitted.asked.length).toBeGreaterThan(0);
    expect(fitted.asked.length).toBeLessThan(many.length);
    expect(fitted.deferred).toHaveLength(many.length - fitted.asked.length);
    expect(fitted.body).toContain(
      `${fitted.deferred.length} more entries are waiting`,
    );
    // The ones that wait are not half-named: nothing of them is in the post.
    for (const entry of fitted.deferred) {
      expect(fitted.body).not.toContain(entry.id);
    }
  });

  it("never cuts a line: every form line in a fitted post is whole", () => {
    const frame = compose(Number.MAX_SAFE_INTEGER, []).body.length;
    const fitted = compose(frame + 1400);
    const whole = new Set<string>([confirmationForm()]);
    for (const entry of fitted.asked) {
      const lines = replyLines(entry.id);
      whole.add(lines.approve);
      whole.add(lines.reject);
      expect(fitted.body).toContain(lines.approve);
      expect(fitted.body).toContain(lines.reject);
    }
    const said = fitted.body
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith(CONFIRMATION_FORM_PREFIX));
    expect(said.length).toBe(fitted.asked.length * 2 + 1);
    for (const line of said) expect(whole.has(line)).toBe(true);
  });

  // The review of #104, HIGH: any bare key may submit a draft, and the claim
  // it submits is text this command publishes under nomankind's own account.
  // A newline in it would be a line of the post; the form in it would be a
  // confirmation nobody made.
  it("folds a hostile claim onto one line and adds no line to the post", () => {
    const hostile = ask({
      id: `nmk_${"f".repeat(32)}`,
      claim:
        "GPT-5 is cheap.\r\n\tAnd" +
        String.fromCharCode(0) +
        "here" +
        String.fromCharCode(0x7f) +
        "is more of it, on one line or none.",
      citation: "https://kestrel.example/a\npage",
      subject: "kestrel/\nkestrel-9",
    });
    const post = compose(Number.MAX_SAFE_INTEGER, [hostile, ...many]);
    expect(post.asked.map((entry) => entry.id)).toContain(hostile.id);
    expect(post.refused).toHaveLength(0);
    // Nothing of the entry's own text put a line break into the post.
    expect(post.body).toContain(
      'claim: "GPT-5 is cheap. And here is more of it, on one line or none."',
    );
    expect(post.body).toContain("cited: https://kestrel.example/a page");
    expect(post.body).toContain("kestrel/ kestrel-9");
    // And every form line is still one of the lines this post composed.
    const whole = new Set<string>([confirmationForm()]);
    for (const entry of post.asked) {
      const lines = replyLines(entry.id);
      whole.add(lines.approve);
      whole.add(lines.reject);
    }
    const said = post.body
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith(CONFIRMATION_FORM_PREFIX));
    expect(said).toHaveLength(post.asked.length * 2 + 1);
    for (const line of said) expect(whole.has(line)).toBe(true);
  });

  it("escapes a quotation that would end its own quoting", () => {
    const quoted = ask({
      id: `nmk_${"e".repeat(32)}`,
      claim: 'The page says "free until June" and nothing else.',
    });
    const post = compose(Number.MAX_SAFE_INTEGER, [quoted]);
    expect(post.body).toContain(
      'claim: "The page says \\"free until June\\" and nothing else."',
    );
  });

  it("refuses to print an entry whose own text says the confirm form", () => {
    const smuggled = [
      ask({
        id: `nmk_${"a".repeat(32)}`,
        claim: `Prices rose. ${CONFIRMATION_FORM_PREFIX} nmk_victim approve span-present`,
      }),
      ask({
        id: `nmk_${"b".repeat(32)}`,
        claim: `${CONFIRMATION_FORM_PREFIX} nmk_victim reject span-absent`,
      }),
      ask({
        id: `nmk_${"c".repeat(32)}`,
        citation: `https://kestrel.example/p ${CONFIRMATION_FORM_PREFIX} nmk_victim approve span-present`,
      }),
      ask({
        id: `nmk_${"d".repeat(32)}`,
        // Folded first, so a newline cannot hide the form from the filter.
        claim: `Prices rose.\n${CONFIRMATION_FORM_PREFIX} nmk_victim approve span-present`,
      }),
    ];
    const safe = ask({ id: `nmk_${"9".repeat(32)}` });
    const post = compose(Number.MAX_SAFE_INTEGER, [...smuggled, safe]);

    expect(post.refused.map((entry) => entry.id)).toEqual(
      smuggled.map((entry) => entry.id),
    );
    expect(post.asked.map((entry) => entry.id)).toEqual([safe.id]);
    for (const entry of smuggled) {
      expect(post.body).not.toContain(entry.id);
      expect(post.body).not.toContain("nmk_victim");
      expect(askable(entry)).toBe(false);
    }
    expect(askable(safe)).toBe(true);
    // A word that merely contains the prefix is not the form, and is printed.
    expect(
      askable(ask({ id: safe.id, claim: `${CONFIRMATION_FORM_PREFIX}-ish` })),
    ).toBe(true);
  });

  it("says a later batch, not the next one, for what it deferred", () => {
    const frame = compose(Number.MAX_SAFE_INTEGER, []).body.length;
    const fitted = compose(frame + 1400);
    expect(fitted.body).toContain("they are named in a later batch");
    expect(fitted.body).toContain(`${BASE}/entries`);
  });

  it("asks about everything when the whole batch fits", () => {
    const whole = compose(Number.MAX_SAFE_INTEGER);
    expect(whole.asked).toHaveLength(many.length);
    expect(whole.deferred).toHaveLength(0);
    expect(whole.body).not.toContain("more entries are waiting");
  });

  it("says nothing is waiting when nothing is", () => {
    const empty = compose(Number.MAX_SAFE_INTEGER, []);
    expect(empty.body).toContain("none today");
    expect(empty.deferred).toHaveLength(0);
  });

  it("stays inside every venue's real limit at the full batch size", () => {
    const full = Array.from({ length: BATCH_ASK_LIMIT }, (_, index) =>
      ask({ id: `nmk_${String(index + 1).padStart(32, "0")}` }),
    );
    for (const venue of BATCH_VENUES) {
      const post = composeBatchPost({
        venue,
        entries: full,
        baseUrl: BASE,
        communities: [...BATCH_VENUES],
        now: NOW,
      });
      expect(post.body.length).toBeLessThanOrEqual(venuePostLimit(venue));
      expect(post.asked.length).toBeGreaterThan(0);
    }
  });

  it("fits the entries per venue that today's frame and instructions leave room for", () => {
    // Measured rather than assumed, and re-measured whenever the post's words
    // move. Two things changed with decision D-145, and both are in the
    // numbers below.
    //
    // Every post names every community the batch went to (D-138 item 12), so a
    // fourth venue lengthens the frame at ALL of them by the ten characters of
    // ", moltbook". At The Colony that is what a tenth entry was living on: it
    // fitted at 9 entries inside 10000 rather than 10. Nobody's ask got
    // smaller by accident — the record now says it asked in four places, and
    // one entry a day waits a day longer at that venue until the log in front
    // of it moves.
    //
    // And Moltbook itself fits five inside the same 8000 the founding registry
    // publishes, where the registry fits six: its binding paragraph is three
    // lines longer, because the field the key goes in is named in the board's
    // own word and the profile door is spelled out for somebody who has to
    // find it.
    //
    // A tripwire and meant to be one. A future word that pushes a venue over
    // drops a whole entry from that day's ask, silently, and this is where it
    // is seen. The fix is to weigh the word against the entry and then update
    // the number here, with the reason.
    const full = Array.from({ length: BATCH_ASK_LIMIT }, (_, index) =>
      ask({ id: `nmk_${String(index + 1).padStart(32, "0")}` }),
    );
    const fits: Readonly<Record<string, number>> = {
      "1f916": 6,
      colony: 9,
      github: 121,
      moltbook: 5,
    };
    for (const venue of BATCH_VENUES) {
      const post = composeBatchPost({
        venue,
        entries: full,
        baseUrl: BASE,
        communities: [...BATCH_VENUES],
        now: NOW,
      });
      expect(post.asked).toHaveLength(fits[venue]!);
      expect(post.body.length).toBeLessThanOrEqual(venuePostLimit(venue));
    }
  });

  // The boards refuse a comment carrying one, and a post nobody could quote
  // back is a post that cannot be answered in place.
  it("carries no email address anywhere, at any venue", () => {
    for (const venue of BATCH_VENUES) {
      const post = composeBatchPost({
        venue,
        entries: many,
        baseUrl: BASE,
        communities: [...BATCH_VENUES],
        now: NOW,
      });
      expect(post.body).not.toMatch(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
      expect(post.title).not.toContain("@");
    }
  });
});

describe("a venue's challenge, printed and not answered", () => {
  const posted = { id: "9c2e", url: "https://moltbook.example/post/9c2e" };

  it("says nothing at all for a post no venue challenged", () => {
    expect(challengeLines("moltbook", posted)).toEqual([]);
    expect(challengeLines("colony", { ...posted })).toEqual([]);
  });

  it("folds every one of the board's four strings onto its own line", () => {
    // The review of #109. A newline in a code or an expiry writes a line of
    // this command's own stdout — the reviewer produced a convincing
    // `posted moltbook <id> <url>` that way — and breaks the JSON of the
    // printed call into something nobody can paste. All four are a server's
    // strings, so all four go through the same folder the composer puts a
    // stranger's claim through, and not only the two that read like prose.
    const lines = challengeLines("moltbook", {
      ...posted,
      challenge: {
        verification_code: `vc_7731"}\nposted moltbook forged https://evil.example/1\n{"x":"`,
        challenge_text: "three spiders\nminus a baker's dozen",
        expires_at: "2026-09-19T00:05:00.000Z\nposted moltbook forged https://evil.example/2",
        instructions: "answer it\nwithin five minutes",
        door: "https://www.moltbook.com/api/v1/verify",
      },
    });

    for (const line of lines) {
      expect(line).not.toContain("\n");
      expect(line).not.toContain("\r");
    }
    // Not one forged line anywhere in it: every line the command printed is
    // one the command wrote.
    expect(lines.some((line) => line.startsWith("posted "))).toBe(false);
    // And the call is still a call. Folding alone would not have got here: the
    // code above also carries a quotation mark and a brace, which break a
    // hand-spelled object exactly as a newline breaks a line, so the body is
    // built by `JSON.stringify` and escaped.
    const call = lines[lines.length - 1]!;
    expect(call.startsWith("answer it yourself with: POST ")).toBe(true);
    const json = call.slice(call.indexOf("{"));
    expect(() => JSON.parse(json) as unknown).not.toThrow();
    expect((JSON.parse(json) as { answer: string }).answer).toBe("<your answer>");
  });

  it("leaves out an expiry and instructions the board did not give", () => {
    const lines = challengeLines("moltbook", {
      ...posted,
      challenge: {
        verification_code: "vc_7731",
        challenge_text: "what is two and two",
        expires_at: null,
        instructions: null,
        door: "https://www.moltbook.com/api/v1/verify",
      },
    });
    expect(lines.some((line) => line.startsWith("expires_at "))).toBe(false);
    expect(lines.some((line) => line.startsWith("instructions "))).toBe(false);
    expect(lines).toHaveLength(4);
  });
});

describe("the run", () => {
  /** What the entry door answers for the two entries the listing is asking about. */
  const doors = new Map<string, AskEntry>([
    [DRAFT_A, ask({ id: DRAFT_A })],
    [
      LABELLED,
      ask({
        id: LABELLED,
        status: "verified",
        bootstrap: "fixtures",
        domain: "ai-safety",
        subject: "kestrel/kestrel-3",
      }),
    ],
  ]);

  function fixture(state: StateStore) {
    const http = new FakeHttp((path) => {
      if (path === "/entries") return listing();
      const id = path.startsWith("/entries/")
        ? path.slice("/entries/".length)
        : null;
      const entry = id === null ? undefined : doors.get(id);
      return entry === undefined ? { status: 404, body: null } : entryDoor(entry);
    });
    const io = lines();
    const posters = new Map(
      BATCH_VENUES.map((venue) => [venue, new FakePoster(venue)] as const),
    );
    return { http, io, posters, deps: deps({ http, io, state, posters }) };
  }

  it("posts once to every community asked, and records the day", async () => {
    const state = memoryState();
    const run = fixture(state);
    expect(await runBatchPost(["all", BASE], run.deps)).toBe(0);
    for (const venue of BATCH_VENUES) {
      expect(run.posters.get(venue)?.sent).toHaveLength(1);
      expect(run.io.out.some((line) => line.startsWith(`posted ${venue} `))).toBe(true);
    }
    const written = parseState(state.written[state.written.length - 1] ?? null);
    for (const venue of BATCH_VENUES) {
      expect(postedOn(written, venue, utcDay(NOW))).toBe(true);
    }
  });

  it("prints Moltbook's challenge, answers none of it, and keeps the day", async () => {
    // Decision D-145 item 4. The board may accept the post and then ask the
    // poster a word problem. A machine of this record's never solves a puzzle
    // nobody asked it to solve: the run prints the board's own words, the code
    // and the exact call that answers it, and a person decides.
    //
    // The post exists — the board gave it an id — so the day is spent and the
    // state records it. A run that called this a failure would post again
    // tomorrow and the day after, which is the one thing the daily bound is
    // for.
    const state = memoryState();
    const run = fixture(state);
    const challenged = new ChallengingPoster("moltbook");
    run.posters.set("moltbook", challenged as unknown as FakePoster);

    // Exit 3 and not 0: 0 and 1 already mean two things an unattended run acts
    // on — the batch was said, or a board refused it — and a post sitting
    // behind an unanswered puzzle is neither (the review of #109).
    expect(await runBatchPost(["moltbook", BASE], run.deps)).toBe(3);
    expect(challenged.sent).toHaveLength(1);
    expect(run.io.out).toContain(`posted moltbook ${CHALLENGE_POST_ID} https://moltbook.example/post/1`);
    expect(
      run.io.out.some((line) =>
        line.startsWith(`pending verification moltbook ${CHALLENGE_POST_ID}:`),
      ),
    ).toBe(true);
    expect(run.io.out).toContain(
      "challenge moltbook: Take the number of legs on three spiders, subtract a baker's dozen.",
    );
    expect(run.io.out).toContain("verification_code moltbook: vc_7731");
    expect(run.io.out).toContain("expires_at moltbook: 2026-09-19T00:05:00.000Z");
    expect(
      run.io.out.some(
        (line) =>
          line.startsWith("answer it yourself with: POST ") &&
          line.includes("https://moltbook.example/api/v1/verify") &&
          line.includes('"verification_code":"vc_7731"') &&
          line.includes('"answer":"<your answer>"'),
      ),
    ).toBe(true);
    // And nothing was sent twice: one post, no second call, no answer. The
    // puzzle's own arithmetic appears nowhere in the run's output, because the
    // run never did it.
    expect(run.io.out.some((line) => line.startsWith("answer moltbook"))).toBe(
      false,
    );
    // Said on stderr as well, which is where an unattended run's output is
    // read when it is read at all: with the exit code, that is the whole
    // difference between a post the world can see and a post nobody can.
    expect(run.io.err).toHaveLength(1);
    expect(run.io.err[0]).toBe(
      `pending verification moltbook ${CHALLENGE_POST_ID}: the board accepted ` +
        `the post and asked for a verification answer, which this run does not solve.`,
    );

    const written = parseState(state.written[state.written.length - 1] ?? null);
    expect(postedOn(written, "moltbook", utcDay(NOW))).toBe(true);
    expect(written["moltbook"]?.id).toBe(CHALLENGE_POST_ID);
  });

  it("refuses a second batch to the same community on the same UTC day", async () => {
    const day = utcDay(NOW);
    const state = memoryState(
      JSON.stringify({
        "1f916": { date: day, id: "1", url: "https://1f916.example/1" },
      }),
    );
    const run = fixture(state);
    expect(await runBatchPost(["all", BASE], run.deps)).toBe(0);
    expect(run.posters.get("1f916")?.sent).toHaveLength(0);
    expect(run.io.out).toContain(`skipped 1f916: already posted on ${day}`);
    // The others are a different community and are asked as usual.
    expect(run.posters.get("colony")?.sent).toHaveLength(1);
    expect(run.posters.get("github")?.sent).toHaveLength(1);
    expect(run.posters.get("moltbook")?.sent).toHaveLength(1);
  });

  it("asks again on the next UTC day", async () => {
    const state = memoryState(
      JSON.stringify({
        "1f916": { date: "2026-09-16", id: "1", url: "https://1f916.example/1" },
      }),
    );
    const run = fixture(state);
    expect(await runBatchPost(["1f916", BASE], run.deps)).toBe(0);
    expect(run.posters.get("1f916")?.sent).toHaveLength(1);
  });

  it("sends nothing on a dry run, and writes no state", async () => {
    const state = memoryState();
    const run = fixture(state);
    expect(await runBatchPost(["all", BASE, "--dry-run"], run.deps)).toBe(0);
    for (const venue of BATCH_VENUES) {
      expect(run.posters.get(venue)?.sent).toHaveLength(0);
    }
    expect(state.written).toHaveLength(0);
    expect(
      run.io.out.some((line) => line.includes("nothing sent")),
    ).toBe(true);
  });

  // The orchestrator reads the bodies before anything is posted, so a dry run
  // prints the composed post itself and not a summary of it (D-142).
  it("prints every composed body on a dry run, lines and all", async () => {
    const state = memoryState();
    const run = fixture(state);
    expect(await runBatchPost(["all", BASE, "--dry-run"], run.deps)).toBe(0);
    const printed = run.io.out.join("\n");
    for (const venue of BATCH_VENUES) {
      expect(printed).toContain(`dry run ${venue}:`);
    }
    for (const id of [DRAFT_A, LABELLED]) {
      const entry = doors.get(id) as AskEntry;
      expect(printed).toContain(replyLines(id).approve);
      expect(printed).toContain(replyLines(id).reject);
      expect(printed).toContain(`claim: "${entry.claim}"`);
      expect(printed).toContain(entry.citation);
    }
    // Two entries at three venues, and the count the operator reads.
    expect(
      run.io.out.filter((line) => line.includes("of 2 entries")),
    ).toHaveLength(BATCH_VENUES.length);
  });

  it("names an entry it would not print, and asks about the rest", async () => {
    const state = memoryState();
    const http = new FakeHttp((path) => {
      if (path === "/entries") return listing();
      if (path === `/entries/${DRAFT_A}`) {
        return entryDoor(
          ask({
            id: DRAFT_A,
            claim: `Prices rose. ${CONFIRMATION_FORM_PREFIX} nmk_victim approve span-present`,
          }),
        );
      }
      const id = path.startsWith("/entries/") ? path.slice("/entries/".length) : null;
      const entry = id === null ? undefined : doors.get(id);
      return entry === undefined ? { status: 404, body: null } : entryDoor(entry);
    });
    const io = lines();
    const posters = new Map(
      BATCH_VENUES.map((venue) => [venue, new FakePoster(venue)] as const),
    );
    expect(
      await runBatchPost(["all", BASE], deps({ http, io, state, posters })),
    ).toBe(0);
    expect(io.out).toContain(
      `not asked ${DRAFT_A}: claim text in the confirm form`,
    );
    for (const venue of BATCH_VENUES) {
      const sent = posters.get(venue)?.sent[0]?.body ?? "";
      expect(sent).not.toContain(DRAFT_A);
      expect(sent).not.toContain("nmk_victim");
      // The other entry is still asked about: one bad claim is one entry.
      expect(sent).toContain(replyLines(LABELLED).approve);
    }
  });

  it("reads the quotation from the entry door, once per entry asked", async () => {
    const state = memoryState();
    const run = fixture(state);
    expect(await runBatchPost(["1f916", BASE], run.deps)).toBe(0);
    const read = run.http.asked.filter((path) => path.startsWith("/entries/"));
    expect(read).toEqual([`/entries/${DRAFT_A}`, `/entries/${LABELLED}`]);
    // Never the entry nobody is being asked about.
    expect(run.http.asked).not.toContain(`/entries/${PLAIN}`);
  });

  it("names a venue that refused, and goes on to the next", async () => {
    const state = memoryState();
    const run = fixture(state);
    const deps: BatchPostDeps = {
      ...run.deps,
      posterFor: async (venue: string, _plan: BatchPlan): Promise<Poster> => {
        if (venue === "colony") throw new Error("colony refused 429: slow down");
        return run.posters.get(venue) as Poster;
      },
    };
    expect(await runBatchPost(["all", BASE], deps)).toBe(1);
    expect(run.io.out.some((line) => line.startsWith("failed colony:"))).toBe(true);
    expect(run.posters.get("github")?.sent).toHaveLength(1);
    // A refusal that names no cap says nothing about the policy table: 429 is
    // the board asking for quiet, and there is no number to carry into it.
    expect(run.io.out.some((line) => line.includes("post_max_chars"))).toBe(false);
  });

  it("names the policy row when a venue refuses a post for its length", async () => {
    // The founding registry's own answer on 2026-09-18, verbatim: the run
    // prints it whole, and adds the one thing it does not say — which row of
    // src/policy.ts holds the number the composer fitted this batch to.
    const answer =
      '1f916 refused 400: {"error":"body too long: the cap is 8000. The cap is ' +
      'published at GET / and in GET /api/surface; a rejected post does not ' +
      'spend your daily post"}';
    const state = memoryState();
    const run = fixture(state);
    const deps: BatchPostDeps = {
      ...run.deps,
      posterFor: async (venue: string, _plan: BatchPlan): Promise<Poster> => {
        if (venue === "1f916") throw new Error(answer);
        return run.posters.get(venue) as Poster;
      },
    };
    expect(await runBatchPost(["all", BASE], deps)).toBe(1);
    expect(run.io.out).toContain(`failed 1f916: ${answer}`);
    const named = run.io.out.find((line) => line.startsWith("change post_max_chars"));
    expect(named).toBeDefined();
    expect(named).toContain("post_max_chars for 1f916 in src/policy.ts");
    expect(named).toContain("cap of 8000");
    // No retry and no re-fit: the refused venue sent nothing, and the run said
    // so rather than quietly asking about fewer entries.
    expect(run.posters.get("1f916")?.sent ?? []).toHaveLength(0);
    expect(run.posters.get("colony")?.sent).toHaveLength(1);
  });

  it("says nothing about the table for a refusal that is only weather", () => {
    // A 5xx that happens to carry the word is a server's bad day and not a
    // published limit, and a status that is not the board's verdict on this
    // post is not the board saying anything about the post at all.
    expect(capRowAdvice("1f916", "1f916 refused 500: cap is 8000")).toBeNull();
    expect(capRowAdvice("colony", "colony refused 429: slow down")).toBeNull();
    expect(capRowAdvice("github", "github refused via gh (1): no token")).toBeNull();
    // And a 4xx that names a cap without a number still names the row.
    const advice = capRowAdvice("colony", "colony refused 413: body too long");
    expect(advice).toContain("post_max_chars for colony in src/policy.ts");
    expect(advice).not.toContain("cap of");
  });

  it("says nothing about the table when the board is counting posts, not characters", () => {
    // The founding registry counts a daily post, and it says so with the same
    // word it says the length limit with. A rate limit is not a row anybody can
    // change: the answer to it is tomorrow, and the post is unspent.
    expect(
      capRowAdvice(
        "1f916",
        '1f916 refused 429: {"error":"you have used your daily post cap; the ' +
          'next one is at 00:00 UTC"}',
      ),
    ).toBeNull();
    // Nor is a cap on anything else this table's business: the word alone
    // counts whatever a board wants to count, so it has to name a length.
    expect(
      capRowAdvice("colony", "colony refused 400: daily post cap reached"),
    ).toBeNull();
    expect(
      capRowAdvice("colony", "colony refused 403: your thread cap is 3"),
    ).toBeNull();
    // A cap on characters, said any of the ways a board says it, still does.
    for (const answer of [
      "colony refused 400: the cap is 8000 characters",
      "colony refused 400: maximum length 8000",
      "colony refused 400: character limit exceeded",
      "colony refused 413: body too large",
    ]) {
      expect(capRowAdvice("colony", answer)).toContain("post_max_chars");
    }
  });

  it("refuses arguments that are not a batch, before any read", async () => {
    const state = memoryState();
    const run = fixture(state);
    expect(await runBatchPost(["mastodon", BASE], run.deps)).toBe(2);
    expect(run.http.asked).toHaveLength(0);
    expect(run.io.err[0]).toContain("usage: batch-post");
  });

  it("writes every body to --out without posting twice", async () => {
    const state = memoryState();
    const run = fixture(state);
    const files = new Map<string, string>();
    const written: BatchPostDeps = {
      ...run.deps,
      writeOut: async (path: string, text: string): Promise<void> => {
        files.set(path, text);
      },
    };
    expect(await runBatchPost(["all", BASE, "--dry-run", "--out", "batch.txt"], written)).toBe(0);
    const file = files.get("batch.txt") ?? "";
    for (const venue of BATCH_VENUES) expect(file).toContain(`--- ${venue} ---`);
  });
});

// ---------------------------------------------------------------------------
// The ask follows the pinned thread (D-145, the operations of 2026-09-19)
// ---------------------------------------------------------------------------

/**
 * A defect found in operations rather than in a test.
 *
 * The daily run opened a new Colony post every day, and the sweep reads exactly
 * the threads pinned in `CONFIRMATION_VENUES` (D-143 item 14) at a venue whose
 * posts it cannot discover. So the first day's ask was pinned and answered, and
 * every day after that spoke into a thread nobody was listening to. The ask now
 * goes where the reading is — a comment on the newest pinned thread — and where
 * nothing is pinned it opens a post and says out loud that the post has to be
 * pinned before anybody can be heard under it.
 */

/** The record's own base URL, production, whose Colony thread is pinned. */
const PRODUCTION = "https://app.nomankind.ai";

/** A poster client that answers canned responses by path, and keeps the calls. */
class FakePosterHttp implements PosterHttp {
  readonly sent: {
    method: string;
    url: string;
    body: unknown;
    authorization: string | null;
  }[] = [];

  constructor(private readonly answer: (path: string) => Canned) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const text = await request.text();
    this.sent.push({
      method: request.method,
      url: request.url,
      body: text === "" ? null : (JSON.parse(text) as unknown),
      authorization: request.headers.get("authorization"),
    });
    const canned = this.answer(url.pathname);
    return new Response(JSON.stringify(canned.body), {
      status: canned.status,
      headers: { "content-type": "application/json" },
    });
  }
}

/** The Colony's own preamble: the key buys a token, then whichever door. */
function colonyDoors(answer: (path: string) => Canned): (path: string) => Canned {
  return (path: string): Canned => {
    if (path === "/api/v1/auth/token") {
      return { status: 200, body: { access_token: "tok_1" } };
    }
    return answer(path);
  };
}

/** One Colony poster over a fake board, with or without a thread to follow. */
function colonyPoster(
  http: PosterHttp,
  thread: string | number | null,
): ColonyPoster {
  return new ColonyPoster({
    venue: "colony",
    origin: "https://thecolony.ai",
    apiKey: "the-secret",
    colony: "general",
    postType: "discussion",
    thread,
    http,
  });
}

describe("which thread the daily ask is said on", () => {
  it("reads the environment off the base URL it was given", () => {
    // The one table that maps the three deployments to the three hostnames
    // (src/mirror.ts), read the other way round rather than copied.
    expect(environmentOfBaseUrl(PRODUCTION)).toBe("production");
    expect(environmentOfBaseUrl("https://demo.nomankind.ai/")).toBe("demo");
    expect(environmentOfBaseUrl("http://localhost:8787")).toBe("local");
    // Anything this record does not publish reads as local, which pins nothing
    // anywhere: a run against a hostname nobody declared opens its own post
    // rather than commenting on a thread it guessed at.
    expect(environmentOfBaseUrl(BASE)).toBe("local");
    expect(environmentOfBaseUrl("not a url")).toBe("local");
  });

  it("follows the pin at the venues whose posts cannot be discovered", () => {
    // The shape of the defect and not a list of names: a venue follows the pin
    // when the board does not list its citizen's posts and its threads are that
    // citizen's own. GitHub's thread is an issue named on the command line, and
    // the founding registry's posts are discovered above the pinned floor.
    for (const venue of ["colony", "moltbook"]) {
      expect(followsPin(venue)).toBe(true);
    }
    for (const venue of ["1f916", "github"]) {
      expect(followsPin(venue)).toBe(false);
    }
  });

  it("takes the newest thread the maintainer pinned for this environment", () => {
    const colony = CONFIRMATION_VENUES.find((row) => row.venue === "colony");
    const pinned = colony?.threads["production"] ?? [];
    expect(pinned.length).toBeGreaterThan(0);
    expect(pinnedThreadFor("colony", "production")).toBe(
      pinned[pinned.length - 1],
    );
    // Nothing pinned is null and never an invented thread: Moltbook's account
    // does not exist yet (D-145), and local reads no board anywhere.
    expect(pinnedThreadFor("moltbook", "production")).toBeNull();
    expect(pinnedThreadFor("colony", "local")).toBeNull();
    expect(pinnedThreadFor("nowhere", "production")).toBeNull();
  });

  it("says, before it posts, when the ask is about to open an unread post", () => {
    expect(pinNote("colony", PRODUCTION)).toBeNull();
    const note = pinNote("moltbook", PRODUCTION);
    expect(note).toContain("no pin moltbook");
    expect(note).toContain("production");
    expect(note).toContain("CONFIRMATION_VENUES (src/policy.ts)");
    expect(note).toContain("nothing said under it is read");
    // Not a line about the venues this was never true of.
    expect(pinNote("github", BASE)).toBeNull();
    expect(pinNote("1f916", BASE)).toBeNull();
  });
});

describe("the Colony poster, on a pinned thread and off one", () => {
  const body: PostBody = { title: "nomankind: 2 entries", body: "the ask" };

  it("comments on the thread it was handed, and names both in the URL", async () => {
    const http = new FakePosterHttp(
      colonyDoors(() => ({ status: 201, body: { id: "aec1028d" } })),
    );
    const posted = await colonyPoster(http, "bae0e581").post(body);

    // The call .tools/colony.mjs's `reply` makes, and the one the orchestrator
    // made by hand on 2026-09-19: the comment door of that post, with `body`.
    expect(http.sent[1]?.method).toBe("POST");
    expect(http.sent[1]?.url).toBe(
      "https://thecolony.ai/api/v1/posts/bae0e581/comments",
    );
    expect(http.sent[1]?.body).toEqual({ body: "the ask" });
    expect(http.sent[1]?.authorization).toBe("Bearer tok_1");
    // No colonies listing: a comment needs no colony id, so none is asked for.
    expect(http.sent).toHaveLength(2);
    // The URL names the thread and the comment, which is the whole of what an
    // operator needs to go and look.
    expect(posted.id).toBe("aec1028d");
    expect(posted.url).toBe(
      "https://thecolony.ai/posts/bae0e581#comment-aec1028d",
    );
  });

  it("opens a post in the colony when no thread is pinned", async () => {
    const http = new FakePosterHttp(
      colonyDoors((path) =>
        path === "/api/v1/colonies"
          ? { status: 200, body: { colonies: [{ id: "col_7", name: "general" }] } }
          : { status: 201, body: { id: "post_9" } },
      ),
    );
    const posted = await colonyPoster(http, null).post(body);

    expect(http.sent.map((each) => new URL(each.url).pathname)).toEqual([
      "/api/v1/auth/token",
      "/api/v1/colonies",
      "/api/v1/posts",
    ]);
    expect(http.sent[2]?.body).toEqual({
      colony_id: "col_7",
      post_type: "discussion",
      title: body.title,
      body: body.body,
    });
    expect(posted.url).toBe("https://thecolony.ai/posts/post_9");
  });

  it("passes a refusal of the comment through, and names no credential", async () => {
    const http = new FakePosterHttp(
      colonyDoors(() => ({ status: 413, body: { error: "body too long" } })),
    );
    const poster = colonyPoster(http, "bae0e581");
    // The refusal path is the one it always was: the venue's own words, and
    // the policy row named beside them for a cap on length. A comment may have
    // a smaller cap than a post, and `post_max_chars` is still the bound the
    // composer fits to, so a board that refuses one is a board publishing a
    // limit the table should carry.
    await expect(poster.post(body)).rejects.toThrow(
      /colony refused 413: .*body too long/,
    );
    await expect(poster.post(body)).rejects.not.toThrow(/the-secret/);
    expect(capRowAdvice("colony", "colony refused 413: body too long")).toContain(
      "post_max_chars for colony in src/policy.ts",
    );
  });

  it("refuses to invent an id for a comment the board named none for", async () => {
    const http = new FakePosterHttp(colonyDoors(() => ({ status: 201, body: {} })));
    await expect(colonyPoster(http, "bae0e581").post(body)).rejects.toThrow(
      /named no id/,
    );
  });
});

describe("the Moltbook poster, on a pinned thread", () => {
  const body: PostBody = { title: "nomankind: 2 entries", body: "the ask" };

  function moltbook(thread: string | null, http: PosterHttp): MoltbookPoster {
    return new MoltbookPoster({
      venue: "moltbook",
      origin: "https://www.moltbook.com",
      apiKey: "the-secret",
      submolt: "general",
      thread,
      http,
    });
  }

  it("comments under the key, with the board's own content field", async () => {
    const http = new FakePosterHttp(() => ({
      status: 200,
      body: { success: true, comment: { id: "cmt_4f" } },
    }));
    const posted = await moltbook("2b1c-uuid", http).post(body);

    expect(http.sent).toHaveLength(1);
    expect(http.sent[0]?.url).toBe(
      "https://www.moltbook.com/api/v1/posts/2b1c-uuid/comments",
    );
    expect(http.sent[0]?.body).toEqual({ content: "the ask" });
    expect(http.sent[0]?.authorization).toBe("Bearer the-secret");
    expect(posted.id).toBe("cmt_4f");
    expect(posted.url).toBe(
      "https://www.moltbook.com/post/2b1c-uuid#comment-cmt_4f",
    );
    expect(posted.challenge).toBeUndefined();
  });

  it("carries a challenge off the comment door back whole, and solves none", async () => {
    // D-145 item 4, at the second door: the board may hold a comment behind the
    // same puzzle it holds a post behind, and a door that quietly did the
    // arithmetic would be the rule holding only where somebody wrote it out.
    const http = new FakePosterHttp(() => ({
      status: 200,
      body: {
        success: true,
        comment: { id: "cmt_4f" },
        verification_required: true,
        verification: {
          verification_code: "vc_7731",
          challenge_text: "How many legs on three spiders, less a baker's dozen?",
          expires_at: "2026-09-19T00:05:00.000Z",
        },
      },
    }));
    const posted = await moltbook("2b1c-uuid", http).post(body);

    expect(posted.id).toBe("cmt_4f");
    expect(posted.challenge).toEqual({
      verification_code: "vc_7731",
      challenge_text: "How many legs on three spiders, less a baker's dozen?",
      expires_at: "2026-09-19T00:05:00.000Z",
      instructions: null,
      door: "https://www.moltbook.com/api/v1/verify",
    });
    // One call and one only: the verify door was never touched.
    expect(http.sent).toHaveLength(1);
    // And the run prints it, on stdout and on stderr, and exits 3: the comment
    // exists, the day is spent, and a person answers the puzzle or nobody does.
    const printed = challengeLines("moltbook", posted);
    expect(printed[0]).toContain("pending verification moltbook cmt_4f");
    expect(printed).toContain(
      "challenge moltbook: How many legs on three spiders, less a baker's dozen?",
    );
  });

  it("opens a post in the submolt when no thread is pinned", async () => {
    const http = new FakePosterHttp(() => ({
      status: 200,
      body: { success: true, post: { id: "9c2e" } },
    }));
    const posted = await moltbook(null, http).post(body);
    expect(http.sent[0]?.url).toBe("https://www.moltbook.com/api/v1/posts");
    expect(http.sent[0]?.body).toEqual({
      submolt_name: "general",
      title: body.title,
      content: body.body,
    });
    expect(posted.url).toBe("https://www.moltbook.com/post/9c2e");
  });

  it("refuses to invent an id for a comment the board named none for", async () => {
    const http = new FakePosterHttp(() => ({ status: 200, body: { success: true } }));
    await expect(moltbook("2b1c-uuid", http).post(body)).rejects.toThrow(
      /named no id/,
    );
  });
});

describe("the run, on a venue whose thread is pinned", () => {
  const doors = new Map<string, AskEntry>([
    [DRAFT_A, ask({ id: DRAFT_A })],
    [LABELLED, ask({ id: LABELLED, status: "verified", bootstrap: "fixtures" })],
  ]);

  function recordDoors(): FakeHttp {
    return new FakeHttp((path) => {
      if (path === "/entries") return listing();
      const id = path.startsWith("/entries/")
        ? path.slice("/entries/".length)
        : null;
      const entry = id === null ? undefined : doors.get(id);
      return entry === undefined ? { status: 404, body: null } : entryDoor(entry);
    });
  }

  /** What `realPoster` builds for The Colony, without reading a key file. */
  function colonyRun(
    board: PosterHttp,
    state: StateStore,
    io: ValidatorIo,
  ): BatchPostDeps {
    return {
      http: recordDoors(),
      io,
      now: NOW,
      state,
      posterFor: async (venue: string, plan: BatchPlan): Promise<Poster> =>
        colonyPoster(
          board,
          pinnedThreadFor(venue, environmentOfBaseUrl(plan.baseUrl)),
        ),
    };
  }

  it("comments on the pinned Colony thread and records the comment", async () => {
    const thread = String(pinnedThreadFor("colony", "production"));
    const board = new FakePosterHttp(
      colonyDoors(() => ({ status: 201, body: { id: "aec1028d" } })),
    );
    const state = memoryState();
    const io = lines();

    expect(await runBatchPost(["colony", PRODUCTION], colonyRun(board, state, io))).toBe(0);
    expect(board.sent[1]?.url).toBe(
      `https://thecolony.ai/api/v1/posts/${thread}/comments`,
    );

    // The title the post door would have carried is the body's own first line,
    // and it is not said twice: the comment door takes no title, so the body is
    // the whole of the ask, exactly as GitHub's comment has always been.
    const sent = (board.sent[1]?.body as { body: string }).body;
    const title = `nomankind: 2 entries asking for a check (${utcDay(NOW)})`;
    expect(sent.split("\n")[0]).toBe(title);
    expect(sent.split(title)).toHaveLength(2);

    // The state names the comment and a URL that names the thread and the
    // comment, so the operator and tomorrow's run read the same place.
    const written = parseState(state.written[state.written.length - 1] ?? null);
    expect(written["colony"]).toEqual({
      date: utcDay(NOW),
      id: "aec1028d",
      url: `https://thecolony.ai/posts/${thread}#comment-aec1028d`,
    });
    expect(io.out).toContain(
      `posted colony aec1028d https://thecolony.ai/posts/${thread}#comment-aec1028d`,
    );
    // And no note, because there is a pin: the line means what it says.
    expect(io.out.some((line) => line.startsWith("no pin"))).toBe(false);
  });

  it("opens a post and says it must be pinned where nothing is", async () => {
    const board = new FakePosterHttp(
      colonyDoors((path) =>
        path === "/api/v1/colonies"
          ? { status: 200, body: { colonies: [{ id: "col_7", name: "general" }] } }
          : { status: 201, body: { id: "post_9" } },
      ),
    );
    const state = memoryState();
    const io = lines();

    // BASE is nobody's deployment, so it reads as local, where no thread is
    // pinned at all: the ask is still said, as a post, and the run says what
    // that costs before it says it.
    expect(await runBatchPost(["colony", BASE], colonyRun(board, state, io))).toBe(0);
    expect(new URL(board.sent[2]?.url ?? "").pathname).toBe("/api/v1/posts");
    expect(io.out).toContain(pinNote("colony", BASE));
    expect(io.out).toContain(
      "posted colony post_9 https://thecolony.ai/posts/post_9",
    );
  });

  it("says the note on a dry run too, and sends nothing", async () => {
    const state = memoryState();
    const io = lines();
    const posters = new Map(
      BATCH_VENUES.map((venue) => [venue, new FakePoster(venue)] as const),
    );
    const run = deps({ http: recordDoors(), io, state, posters });
    expect(await runBatchPost(["all", BASE, "--dry-run"], run)).toBe(0);
    expect(io.out).toContain(pinNote("colony", BASE));
    expect(io.out).toContain(pinNote("moltbook", BASE));
    expect(io.out.filter((line) => line.startsWith("no pin "))).toHaveLength(2);
    expect(state.written).toHaveLength(0);
  });

  it("folds a board's id and URL onto the one line it prints them on", async () => {
    // The fault #109 fixed for the challenge fields, at the door beside them:
    // both of these are a board's own strings, and a newline in either writes a
    // line of this run's stdout that the run never said — a convincing second
    // `posted ...` for a post that does not exist.
    const forged = "posted colony forged-9 https://thecolony.ai/posts/evil";
    const id = `aec1028d\n${forged}`;
    const url = `https://thecolony.ai/posts/1\nposted moltbook f2 https://x`;
    const state = memoryState();
    const io = lines();
    const run: BatchPostDeps = {
      http: recordDoors(),
      io,
      now: NOW,
      state,
      posterFor: async (venue: string): Promise<Poster> => ({
        venue,
        post: async (): Promise<Posted> => ({ id, url }),
      }),
    };

    expect(await runBatchPost(["colony", PRODUCTION], run)).toBe(0);
    // One line, and not the one the board tried to write.
    const said = io.out.filter((line) => line.startsWith("posted "));
    expect(said).toHaveLength(1);
    expect(said[0]).toBe(
      `posted colony aec1028d ${forged} https://thecolony.ai/posts/1 ` +
        "posted moltbook f2 https://x",
    );
    expect(io.out).not.toContain(forged);

    // And the file keeps what the board actually said, whatever is in it: it
    // is JSON, which escapes a newline rather than being broken by one, and
    // the once-a-day check and the link have to be the board's own strings.
    const text = state.written[state.written.length - 1] ?? null;
    expect(text).toContain("\\n");
    const written = parseState(text);
    expect(written["colony"]).toEqual({ date: utcDay(NOW), id, url });
    expect(postedOn(written, "colony", utcDay(NOW))).toBe(true);
  });

  it("keeps the pin note off the venues that never had one", async () => {
    // Production pins The Colony's thread and GitHub's issue, and the founding
    // registry discovers its own posts above the pinned floor. Moltbook is the
    // one venue with nothing pinned anywhere, because its account does not
    // exist yet (D-145).
    const state = memoryState();
    const io = lines();
    const posters = new Map(
      BATCH_VENUES.map((venue) => [venue, new FakePoster(venue)] as const),
    );
    const run = deps({ http: recordDoors(), io, state, posters });
    expect(await runBatchPost(["all", PRODUCTION, "--dry-run"], run)).toBe(0);
    expect(io.out.filter((line) => line.startsWith("no pin "))).toEqual([
      pinNote("moltbook", PRODUCTION),
    ]);
  });
});

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
  BATCH_VENUES,
  batchPostPlan,
  carriesConfirmForm,
  composeBatchPost,
  confirmationForm,
  entryIdsInHtml,
  oneLine,
  parseState,
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
import type { PostBody, Posted, Poster } from "../src/adapters/poster.js";
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
  it("folds every C0 control, and a run of them, to one space", () => {
    expect(oneLine("a\r\nb")).toBe("a b");
    expect(oneLine(`a${String.fromCharCode(0)}b`)).toBe("a b");
    expect(oneLine(`a${String.fromCharCode(0x7f)}b`)).toBe("a b");
    expect(oneLine("a\t\t\t b")).toBe("a  b");
    expect(oneLine("already one line")).toBe("already one line");
    // Nothing above the controls is touched, so a quotation stays a quotation.
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
    const [registry, colony, github] = bodies;
    expect(registry?.body).toContain("/api/seal");
    expect(registry?.body).toContain("confirm-1f916.mjs");
    expect(colony?.body).toContain("nomankind-key:");
    expect(colony?.body).not.toContain("/api/seal");
    expect(github?.body).toContain("nomankind-key:");
    expect(github?.body).not.toContain("/api/seal");
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
    // The other two are a different community and are asked as usual.
    expect(run.posters.get("colony")?.sent).toHaveLength(1);
    expect(run.posters.get("github")?.sent).toHaveLength(1);
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

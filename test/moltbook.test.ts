/**
 * Moltbook: the doors, the reader and the poster (decision D-145).
 *
 * An agent social network admitted as a confirmation venue on the same footing
 * as The Colony — a `profile` binding, the account rung under it unchanged, one
 * more community under the floor that says a consensus may not come from one
 * board. Nothing about the counting rules moved; what is new is a surface that
 * is shaped differently from the two this record already reads, and everything
 * below is about reading that shape honestly.
 *
 * The fixtures are the shapes the board really serves, read from its own public
 * doors on 2026-09-19 (all GET, no credential):
 *
 * - `GET /api/v1/posts/<uuid>/comments?sort=new&limit=100` answers
 *   `{success, comments, has_more, next_cursor}`, a hundred ROOT comments at a
 *   time, each carrying its whole `replies` tree nested inside it, its author
 *   under `author.name` and its text under `content`.
 * - `GET /api/v1/agents/profile?name=<name>` answers `{success, agent:{...}}`
 *   whose `description` is where a key is published and whose `created_at` is
 *   the account's own beginning, and 404s an agent it does not know.
 * - `POST /api/v1/posts` takes `{submolt_name, title, content}` and may answer
 *   an accepted post with a verification challenge.
 *
 * Three things are proved, in the order the bytes travel.
 *
 * The reader. Replies are flattened so a nested one is a comment like any
 * other, pages are followed by the board's own cursor, a deleted row is passed
 * over while its replies are still read, and a row that is not a comment is not
 * invented into one.
 *
 * The profile. The key is read out of the one field the agent filled in about
 * itself and out of no other, the creation date is read out of the envelope
 * this venue wraps its agent in, and an agent the board does not know is null
 * rather than a guess.
 *
 * The poster. A challenge the board attaches to an accepted post is carried
 * back whole and unanswered — D-145 item 4, a machine of nomankind's never
 * solves a puzzle nobody asked it to solve — and the post's id comes back
 * regardless, because the post exists.
 */

import { describe, expect, it } from "vitest";

import {
  COMMENT_TREE_TOO_DEEP,
  MoltbookBoardAdapter,
  confirmationVenue,
  type BoardComment,
} from "../src/adapters/board.js";
import { MoltbookPoster, type PosterHttp } from "../src/adapters/poster.js";
import { base64urlEncode } from "../src/encoding.js";
import { exportPublicKeyRaw, generateKeypair } from "../src/identity.js";
import {
  CONFIRMATION_COMMENTS_PER_THREAD,
  PROFILE_KEY_PREFIX,
} from "../src/policy.js";

const VENUE = confirmationVenue("moltbook")!;
const ORIGIN = VENUE.origin;
const THREAD = "19b6e9bf-6ff9-4ea5-834a-cbbac714f546";
const HANDLE = "field-notes";

/** A public key, spelled as an agent would publish one. */
async function publicKey(): Promise<string> {
  const pair = await generateKeypair();
  return base64urlEncode(await exportPublicKeyRaw(pair.publicKey));
}

/**
 * The fetcher a test injects: canned bodies by URL, and what was asked.
 *
 * A fragment never reaches a server, so it is cut before the lookup — which is
 * what makes a permalink with one a door this adapter may fetch: the bytes
 * captured are the page's, and the fragment says which comment inside them the
 * line was read from.
 */
function fetcherFor(
  bodies: Readonly<Record<string, string>>,
  asked: string[],
): typeof fetch {
  return (async (url: string) => {
    asked.push(url);
    const body = bodies[url.split("#")[0]!];
    if (body === undefined) {
      return new Response(
        JSON.stringify({ statusCode: 404, message: "Not Found" }),
        { status: 404, headers: { "content-type": "application/json" } },
      );
    }
    return new Response(body, {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

/** One page of the comments door, as this adapter asks for it. */
function page(
  cursor: string | null,
  limit: number = CONFIRMATION_COMMENTS_PER_THREAD,
): string {
  const query = [
    "sort=new",
    `limit=${Math.min(limit, CONFIRMATION_COMMENTS_PER_THREAD)}`,
    ...(cursor === null ? [] : [`cursor=${encodeURIComponent(cursor)}`]),
  ].join("&");
  return `${ORIGIN}/api/v1/posts/${THREAD}/comments?${query}`;
}

/** One comment row, in the board's own field names. */
function row(
  id: string,
  name: string,
  content: string,
  createdAt: string,
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id,
    post_id: THREAD,
    content,
    author_id: `author-${name}`,
    author: { id: `author-${name}`, name, description: "an agent" },
    upvotes: 0,
    downvotes: 0,
    score: 0,
    reply_count: 0,
    is_deleted: false,
    depth: 0,
    // Read and not acted on: the board sets this `pending` on arrival and
    // `verified` later, so refusing anything but `verified` would refuse most
    // of an honest board.
    verification_status: "pending",
    is_spam: false,
    created_at: createdAt,
    updated_at: createdAt,
    replies: [],
    ...over,
  };
}

/** The door's answer around a list of rows. */
function answer(
  rows: readonly unknown[],
  over: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    success: true,
    post_id: THREAD,
    sort: "new",
    count: rows.length,
    comments: rows,
    has_more: false,
    next_cursor: null,
    ...over,
  });
}

function boardOf(
  bodies: Readonly<Record<string, string>>,
  asked: string[] = [],
): MoltbookBoardAdapter {
  return new MoltbookBoardAdapter({
    venue: VENUE,
    environment: "demo",
    fetch: fetcherFor(bodies, asked),
  });
}

const ids = (comments: readonly BoardComment[] | null): string[] =>
  (comments ?? []).map((comment) => String(comment.id));

// ---------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------

describe("the Moltbook comments door", () => {
  it("flattens a nested reply into a comment like any other", async () => {
    const board = boardOf({
      [page(null)]: answer([
        row("root-1", "someone-else", "good question", "2026-09-06T09:00:00Z", {
          reply_count: 2,
          replies: [
            row(
              "reply-1",
              HANDLE,
              "nomankind-confirm-v1 ... approve",
              "2026-09-06T10:00:00Z",
              {
                depth: 1,
                replies: [
                  row(
                    "reply-1-1",
                    "third-reader",
                    "and I checked it too",
                    "2026-09-06T11:00:00Z",
                    { depth: 2 },
                  ),
                ],
              },
            ),
          ],
        }),
      ]),
    });

    const comments = await board.comments(THREAD, 0, 100);
    // Parent before child, depth first, and then sorted by the clock — which
    // is the same order here, because a reply comes after what it answers.
    expect(ids(comments)).toEqual(["root-1", "reply-1", "reply-1-1"]);
    const reply = comments!.find((each) => each.id === "reply-1")!;
    // A reply carries its own everything: the record has never cared where on
    // a thread somebody stood when they said a line.
    expect(reply.handle).toBe(HANDLE);
    expect(reply.body).toBe("nomankind-confirm-v1 ... approve");
    expect(reply.posted_at).toBe("2026-09-06T10:00:00.000Z");
    expect(reply.thread).toBe(THREAD);
  });

  it("passes over a deleted row and still reads what answered it", async () => {
    const board = boardOf({
      [page(null)]: answer([
        row("gone", "someone-else", "", "2026-09-06T09:00:00Z", {
          is_deleted: true,
          replies: [
            row("kept", HANDLE, "I looked and it is there", "2026-09-06T10:00:00Z", {
              depth: 1,
            }),
          ],
        }),
      ]),
    });
    // A parent removed is not a statement withdrawn by the agents who answered
    // it, so the reply survives its parent.
    expect(ids(await board.comments(THREAD, 0, 100))).toEqual(["kept"]);
  });

  it("follows the board's own cursor while it says there is more", async () => {
    const asked: string[] = [];
    const cursor = "eyJjcmVhdGVkQXQiOiIyMDI2In0=";
    const board = boardOf(
      {
        [page(null)]: answer(
          [row("newer", HANDLE, "the second line", "2026-09-06T11:00:00Z")],
          { has_more: true, next_cursor: cursor },
        ),
        [page(cursor)]: answer([
          row("older", HANDLE, "the first line", "2026-09-06T10:00:00Z"),
        ]),
      },
      asked,
    );

    // Oldest first whatever order the pages came in: the door sorts by `new`,
    // and the cursor this venue keeps is the clock.
    expect(ids(await board.comments(THREAD, 0, 100))).toEqual(["older", "newer"]);
    expect(asked).toEqual([page(null), page(cursor)]);
  });

  it("stops at the page whose has_more is false, and asks no more", async () => {
    const asked: string[] = [];
    const board = boardOf(
      {
        [page(null)]: answer([
          row("only", HANDLE, "one line", "2026-09-06T10:00:00Z"),
        ]),
      },
      asked,
    );
    expect(ids(await board.comments(THREAD, 0, 100))).toEqual(["only"]);
    expect(asked).toHaveLength(1);
  });

  it("takes what was posted at or after the cursor, and no more than the bound", async () => {
    const board = boardOf({
      [page(null)]: answer([
        row("old", HANDLE, "before the cursor", "2026-09-06T09:00:00Z"),
        row("at", HANDLE, "on the cursor", "2026-09-06T10:00:00Z"),
        row("after", HANDLE, "past it", "2026-09-06T11:00:00Z"),
      ]),
    });
    // Inclusive on purpose: two comments written in the same millisecond must
    // not be able to push each other out of a run, and a comment read twice is
    // sealed once by the dedup key on (venue, comment, line).
    expect(
      ids(await board.comments(THREAD, Date.parse("2026-09-06T10:00:00Z"), 100)),
    ).toEqual(["at", "after"]);
  });

  it("leaves the newest comments to the next run when the bound cuts the page", async () => {
    // Oldest first, so a page cut short by the bound leaves the NEWEST to the
    // next run rather than the oldest, and the cursor only ever moves forward
    // over comments this run actually read. The door is asked for the bound it
    // is being read to, which is what the board's own `limit` takes.
    const rows = [
      row("old", HANDLE, "before", "2026-09-06T09:00:00Z"),
      row("at", HANDLE, "during", "2026-09-06T10:00:00Z"),
      row("after", HANDLE, "past it", "2026-09-06T11:00:00Z"),
    ];
    const board = boardOf({ [page(null, 2)]: answer(rows) });
    expect(ids(await board.comments(THREAD, 0, 2))).toEqual(["old", "at"]);
  });

  it("invents nothing out of a row that is not a comment", async () => {
    const board = boardOf({
      [page(null)]: answer([
        "not an object",
        { id: "no-author", content: "hello", created_at: "2026-09-06T10:00:00Z" },
        { id: "no-body", author: { name: HANDLE }, created_at: "2026-09-06T10:00:00Z" },
        {
          id: "no-time",
          author: { name: HANDLE },
          content: "hello",
        },
        row("whole", HANDLE, "all four fields", "2026-09-06T10:00:00Z"),
      ]),
    });
    expect(ids(await board.comments(THREAD, 0, 100))).toEqual(["whole"]);
  });

  it("walks a tree twenty thousand deep without falling over", async () => {
    // The review of #109. A JSON document declares its own nesting for free:
    // this one is about 900 KB, inside `BOARD_READ_MAX_BYTES`, and `JSON.parse`
    // takes it without complaint. Every row is deleted, so the caller's bound
    // is never reached — nothing is ever taken — and a recursive walk descended
    // the whole way and threw `RangeError` at a few thousand levels, into a
    // sweep that was not expecting one.
    //
    // Two things are asserted and both matter. It returns, which is the walk
    // being stacked on the heap rather than on this process's call stack: no
    // input can overflow it at any bound. And it says what it left behind,
    // once, rather than passing a thread it only partly read off as a thread
    // that held nothing.
    const deep = 20_000;
    let chain = "";
    for (let level = 0; level < deep; level += 1) {
      chain += `{"id":"x${level}","is_deleted":true,"replies":[`;
    }
    chain += "]";
    for (let level = 0; level < deep - 1; level += 1) chain += "}]";
    chain += "}";
    const document = `{"success":true,"comments":[${chain}],"has_more":false,"next_cursor":null}`;
    expect(document.length).toBeGreaterThan(500_000);

    const board = boardOf({ [page(null)]: document });
    const comments = await board.comments(THREAD, 0, 100);
    expect(comments).toEqual([]);
    expect(board.readSkips()).toEqual([COMMENT_TREE_TOO_DEEP]);
  });

  it("takes what it can reach inside the bound, and only says so when it stopped", async () => {
    // A live reply sits at depth 0, 1 or 2, so an honest thread is read whole
    // and the reason is never said. The counted line here is three deep.
    const nested = row("depth-3", HANDLE, "the line", "2026-09-06T12:00:00Z", {
      depth: 3,
    });
    const tree = row("depth-0", "someone-else", "a", "2026-09-06T09:00:00Z", {
      replies: [
        row("depth-1", "someone-else", "b", "2026-09-06T10:00:00Z", {
          replies: [
            row("depth-2", "someone-else", "c", "2026-09-06T11:00:00Z", {
              replies: [nested],
            }),
          ],
        }),
      ],
    });
    const board = boardOf({ [page(null)]: answer([tree]) });
    expect(ids(await board.comments(THREAD, 0, 100))).toEqual([
      "depth-0",
      "depth-1",
      "depth-2",
      "depth-3",
    ]);
    expect(board.readSkips()).toEqual([]);
  });

  it("clears what it left behind when the next read reaches everything", async () => {
    // The reason is about the read the caller is being handed, so a thread
    // read whole today must not report yesterday's depth.
    const board = boardOf({
      [page(null)]: answer([
        row("only", HANDLE, "one line", "2026-09-06T10:00:00Z"),
      ]),
    });
    expect(board.readSkips()).toEqual([]);
    await board.comments(THREAD, 0, 100);
    expect(board.readSkips()).toEqual([]);
  });

  it("answers null for a door that did not answer, and an empty list for one with no comments", async () => {
    // Null is the board being down, which the step counts as a skip rather
    // than a failure: a public board not answering is weather, not a rule.
    expect(await boardOf({}).comments(THREAD, 0, 100)).toBeNull();
    const shapeless = boardOf({
      [page(null)]: JSON.stringify({ success: true, post_id: THREAD }),
    });
    expect(await shapeless.comments(THREAD, 0, 100)).toEqual([]);
  });

  it("captures the comment at the page it was read from, naming the comment", async () => {
    const asked: string[] = [];
    const board = boardOf(
      { [page(null)]: answer([]) },
      asked,
    );
    const comment: BoardComment = {
      id: "reply-1",
      thread: THREAD,
      handle: HANDLE,
      body: "a line",
      posted_at: "2026-09-06T10:00:00.000Z",
    };
    const captured = await board.comment!(comment);
    // Moltbook publishes no per-comment door, so the capture is the comments
    // page with the comment named in the fragment — the document the line was
    // read out of, and the one the offline verifier searches, replies and all.
    expect(captured!.url).toBe(`${page(null)}#comment-reply-1`);
    expect(asked).toEqual([`${page(null)}#comment-reply-1`]);
  });
});

// ---------------------------------------------------------------------------
// The profile
// ---------------------------------------------------------------------------

describe("the Moltbook profile door", () => {
  const door = `${ORIGIN}/api/v1/agents/profile?name=${HANDLE}`;

  function profile(over: Record<string, unknown>): string {
    return JSON.stringify({
      success: true,
      agent: {
        id: "15e2b1c3-f7d8-436a-a7a6-0f9bbf088823",
        name: HANDLE,
        display_name: HANDLE,
        description: "an agent that checks facts",
        karma: 12,
        is_verified: false,
        is_claimed: true,
        is_active: true,
        created_at: "2024-03-01T00:00:00.000Z",
        last_active: "2026-09-19T00:00:00.000Z",
        deleted_at: null,
        owner: { x_handle: "someone" },
        labels: [],
        ...over,
      },
    });
  }

  it("reads the account's beginning out of the envelope this venue uses", async () => {
    const asked: string[] = [];
    const board = boardOf({ [door]: profile({}) }, asked);
    const read = await board.profile!(HANDLE);
    // `{success, agent:{..., created_at}}`, so the date is the agent's and not
    // the answer's — which is what makes "older than the entry" a fact a
    // reader can recheck rather than a claim this record makes.
    expect(read!.created_at).toBe("2024-03-01T00:00:00.000Z");
    // One door and one read: the date came back with the bytes the binding is
    // read out of, so there is no second fetch to make.
    expect(asked).toEqual([door]);
    expect(read!.url).toBe(door);
  });

  it("reads the key out of the description, which is this board's bio", async () => {
    const key = await publicKey();
    const board = boardOf({
      [door]: profile({ description: `checks facts ${PROFILE_KEY_PREFIX}${key}` }),
    });
    const read = await board.profile!(HANDLE);
    expect(board.profileKey(new TextDecoder().decode(read!.bytes))).toBe(key);
  });

  it("reads only the field the agent filled in about itself", async () => {
    const key = await publicKey();
    // A key anywhere else the door answers is a fact about the account and not
    // a statement by it: an owner's handle, a label somebody else attached, a
    // display name.
    expect(
      boardOf({}).profileKey(
        profile({
          description: null,
          display_name: `${PROFILE_KEY_PREFIX}${key}`,
          labels: [`${PROFILE_KEY_PREFIX}${key}`],
          owner: { x_handle: `${PROFILE_KEY_PREFIX}${key}` },
        }),
      ),
    ).toBeNull();
    // And bytes that are not a profile at all: answered, never thrown.
    expect(boardOf({}).profileKey("<html>not json</html>")).toBeNull();
    expect(boardOf({}).profileKey("[]")).toBeNull();
    expect(boardOf({}).profileKey(JSON.stringify({ success: true }))).toBeNull();
  });

  it("answers null for an agent the board does not know", async () => {
    // `{"statusCode":404,"message":"Agent not found"}` on the real door, and a
    // 404 is a door that did not answer: the line stays uncounted with a
    // reason rather than counted on a guess.
    expect(await boardOf({}).profile!("nobody-here")).toBeNull();
  });

  it("publishes no creation date it cannot find, and never a guess", async () => {
    const board = boardOf({ [door]: profile({ created_at: "not a date" }) });
    // An account whose age the platform does not publish is an account the
    // rung cannot be reached on, which the sweep counts by name.
    expect((await board.profile!(HANDLE))!.created_at).toBeNull();
  });

  it("holds no registry, because this venue has none", async () => {
    const board = boardOf({});
    expect(await board.sealProof()).toBeNull();
    expect(await board.record()).toBeNull();
    // And no thread anywhere yet: the account does not exist (D-145).
    expect(await board.threads()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The poster
// ---------------------------------------------------------------------------

/** A poster HTTP client that answers one canned response and keeps the request. */
class OnePost implements PosterHttp {
  readonly sent: { url: string; body: unknown; authorization: string | null }[] = [];

  constructor(
    private readonly status: number,
    private readonly answer: unknown,
  ) {}

  async fetch(request: Request): Promise<Response> {
    this.sent.push({
      url: request.url,
      body: JSON.parse(await request.text()) as unknown,
      authorization: request.headers.get("authorization"),
    });
    return new Response(JSON.stringify(this.answer), {
      status: this.status,
      headers: { "content-type": "application/json" },
    });
  }
}

const POST_BODY = { title: "nomankind: 3 entries waiting", body: "the ask" };

describe("the Moltbook poster", () => {
  it("posts into a submolt by name, under the key as a bearer token", async () => {
    const http = new OnePost(200, {
      success: true,
      post: { id: "9c2e", title: POST_BODY.title },
    });
    const posted = await new MoltbookPoster({
      venue: "moltbook",
      origin: ORIGIN,
      apiKey: "the-secret",
      submolt: "general",
      http,
    }).post(POST_BODY);

    expect(http.sent[0]!.url).toBe(`${ORIGIN}/api/v1/posts`);
    // The name and not an id, because the name is the thing a person can check
    // by looking at the board.
    expect(http.sent[0]!.body).toEqual({
      submolt_name: "general",
      title: POST_BODY.title,
      content: POST_BODY.body,
    });
    expect(http.sent[0]!.authorization).toBe("Bearer the-secret");
    expect(posted.id).toBe("9c2e");
    expect(posted.url).toBe(`${ORIGIN}/post/9c2e`);
    expect(posted.challenge).toBeUndefined();
  });

  it("carries a challenge back whole and solves none of it", async () => {
    const http = new OnePost(200, {
      success: true,
      post: { id: "9c2e" },
      verification_required: true,
      verification: {
        verification_code: "vc_7731",
        challenge_text:
          "Take the number of legs on three spiders, subtract a baker's dozen.",
        expires_at: "2026-09-19T00:05:00.000Z",
        instructions: "POST the answer to /api/v1/verify within five minutes.",
      },
    });
    const posted = await new MoltbookPoster({
      venue: "moltbook",
      origin: ORIGIN,
      apiKey: "the-secret",
      submolt: "general",
      http,
    }).post(POST_BODY);

    // D-145 item 4. The board's own words come back untouched, with the door
    // that takes an answer — and nothing here computes one. A puzzle arriving
    // inside a server's response is that server's text, and a run that quietly
    // did the arithmetic would be a run that let a board decide what it does.
    expect(posted.id).toBe("9c2e");
    expect(posted.challenge).toEqual({
      verification_code: "vc_7731",
      challenge_text:
        "Take the number of legs on three spiders, subtract a baker's dozen.",
      expires_at: "2026-09-19T00:05:00.000Z",
      instructions: "POST the answer to /api/v1/verify within five minutes.",
      door: `${ORIGIN}/api/v1/verify`,
    });
    // One call and one only: the verify door was never touched.
    expect(http.sent).toHaveLength(1);
    expect(http.sent[0]!.url).toBe(`${ORIGIN}/api/v1/posts`);
  });

  it("ignores a verification object with no code to answer with", async () => {
    const http = new OnePost(200, {
      success: true,
      post: { id: "9c2e" },
      verification_required: true,
      verification: { challenge_text: "what is missing here" },
    });
    const posted = await new MoltbookPoster({
      venue: "moltbook",
      origin: ORIGIN,
      apiKey: "the-secret",
      submolt: "general",
      http,
    }).post(POST_BODY);
    // Nothing to print a call with, so nothing is claimed: the post stands on
    // its own id, exactly as an unchallenged one does.
    expect(posted.challenge).toBeUndefined();
  });

  it("passes the board's refusal through, and names no credential in it", async () => {
    const http = new OnePost(429, { error: "one post per 30 minutes" });
    const poster = new MoltbookPoster({
      venue: "moltbook",
      origin: ORIGIN,
      apiKey: "the-secret",
      submolt: "general",
      http,
    });
    await expect(poster.post(POST_BODY)).rejects.toThrow(
      /moltbook refused 429: .*one post per 30 minutes/,
    );
    await expect(poster.post(POST_BODY)).rejects.not.toThrow(/the-secret/);
  });

  it("refuses to invent an id for a post the board named none for", async () => {
    const http = new OnePost(200, { success: true });
    const poster = new MoltbookPoster({
      venue: "moltbook",
      origin: ORIGIN,
      apiKey: "the-secret",
      submolt: "general",
      http,
    });
    await expect(poster.post(POST_BODY)).rejects.toThrow(/named no id/);
  });
});

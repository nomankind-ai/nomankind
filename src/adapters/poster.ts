/**
 * Where nomankind says its batch ask out loud: one poster per community.
 *
 * Decision D-138 item 6: asking is nomankind's own work. The record cannot make
 * anybody check an entry, and it must not pretend that silence is agreement, so
 * once per UTC day it posts one batch per community naming the entries that are
 * waiting and how to answer. This module is the last inch of that — how a body
 * becomes a post at each venue — and nothing else: what the body says is
 * composed in src/cli/batch-post.ts, and which entries it names is read off the
 * public doors.
 *
 * One interface and three implementations, because the three venues are three
 * different kinds of place. The 1F916 registry takes a post under a citizen
 * credential. The Colony takes an API key for a token and then a post in a
 * colony. GitHub takes a comment on a pinned issue under a token, or the `gh`
 * CLI when the maintainer would rather not put a token in the environment at
 * all. What they have in common is all the caller needs: a body goes out, and
 * an id and a URL come back, so the run can say where it spoke.
 *
 * No credential is ever printed, logged or put in an error message (D-016,
 * D-058). Every one of them arrives as a string this module was handed and
 * leaves in a request header; a refusal names the status and the venue's own
 * text, bounded, and never the thing that authenticated it.
 *
 * Injected all the way down: the HTTP client and, for `--via-gh`, the command
 * runner. So a test drives every poster in process with no network and no
 * child process, and nothing here reads an environment variable or a file —
 * the command does that, where node: modules are allowed.
 */

/** Somewhere to send a request. The CLI's own client satisfies this. */
export interface PosterHttp {
  fetch(request: Request): Promise<Response>;
}

/** One post, as a venue takes it. */
export interface PostBody {
  readonly title: string;
  readonly body: string;
}

/** Where a post landed: the venue's own id for it, and a URL to read it at. */
export interface Posted {
  readonly id: string;
  readonly url: string;
}

/**
 * One community, ready to be posted to.
 *
 * `venue` is the name the record uses for it — the same string the sealed
 * `public_confirmation` and `community_validation` events carry — so a run can
 * name the communities it asked without a second table mapping one to the
 * other.
 */
export interface Poster {
  readonly venue: string;
  post(body: PostBody): Promise<Posted>;
}

/** A child process, injected so a test never starts one. */
export interface CommandRunner {
  run(
    command: string,
    args: readonly string[],
    input: string,
  ): Promise<{ readonly status: number; readonly stdout: string; readonly stderr: string }>;
}

/** How much of a venue's refusal travels into the error line. */
const REFUSAL_CHARS = 300;

/** The refusal, in one line: the venue, the status, and the venue's own words. */
function refused(venue: string, status: number, text: string): Error {
  return new Error(`${venue} refused ${status}: ${text.slice(0, REFUSAL_CHARS)}`);
}

/** The JSON under a response, or null when there is none to read. */
async function jsonOf(response: Response): Promise<{
  readonly text: string;
  readonly json: Record<string, unknown> | null;
}> {
  const text = await response.text();
  try {
    const parsed: unknown = JSON.parse(text);
    return {
      text,
      json:
        typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
          ? (parsed as Record<string, unknown>)
          : null,
    };
  } catch {
    return { text, json: null };
  }
}

/** A string field off a parsed body, or null. Ids arrive as strings or numbers. */
function idOf(body: Record<string, unknown> | null, ...names: string[]): string | null {
  if (body === null) return null;
  for (const name of names) {
    const value = body[name];
    if (typeof value === "string" && value !== "") return value;
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
  }
  return null;
}

/**
 * The founding registry (1F916): one post under nomankind's citizen credential.
 *
 * Exactly what .tools/post-1f916.mjs does by hand — `POST /api/post` with a
 * title and a body, the credential as a bearer token — because the batch post
 * and the maintainer's own posts have to be the same act to the board. The
 * registry allows one post per UTC day, which is the same bound the command
 * keeps for itself in its state file; a refused post spends nothing.
 */
export class RegistryPoster implements Poster {
  readonly venue: string;

  constructor(
    private readonly input: {
      readonly venue: string;
      readonly origin: string;
      /** The citizen credential. Read from a file by the command, never printed. */
      readonly credential: string;
      readonly http: PosterHttp;
    },
  ) {
    this.venue = input.venue;
  }

  async post(body: PostBody): Promise<Posted> {
    const response = await this.input.http.fetch(
      new Request(`${this.input.origin}/api/post`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          authorization: `Bearer ${this.input.credential}`,
        },
        body: JSON.stringify({ title: body.title, body: body.body }),
      }),
    );
    const { text, json } = await jsonOf(response);
    if (!response.ok) throw refused(this.venue, response.status, text);
    const id = idOf(json, "post_id", "id");
    if (id === null) throw new Error(`${this.venue} accepted the post and named no id`);
    return { id, url: `${this.input.origin}/api/post/${id}` };
  }
}

/**
 * The Colony: a token from the API key, then a post in one colony.
 *
 * Two calls and a lookup, as .tools/colony.mjs does them: the key buys a
 * short-lived token, the colonies are listed to turn the colony's name into the
 * id the post door takes, and the post goes out under the token. The name is
 * asked for rather than the id, because the name is the thing a person can
 * check by looking at the board.
 */
export class ColonyPoster implements Poster {
  readonly venue: string;

  constructor(
    private readonly input: {
      readonly venue: string;
      readonly origin: string;
      /** The Colony api_key, read from a key file by the command, never printed. */
      readonly apiKey: string;
      /** The colony the post is filed in, by its own name. */
      readonly colony: string;
      /** The board's own word for what kind of post this is. */
      readonly postType: string;
      readonly http: PosterHttp;
    },
  ) {
    this.venue = input.venue;
  }

  private async token(): Promise<string> {
    const response = await this.input.http.fetch(
      new Request(`${this.input.origin}/api/v1/auth/token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ api_key: this.input.apiKey }),
      }),
    );
    const { text, json } = await jsonOf(response);
    if (!response.ok) throw refused(this.venue, response.status, text);
    const token = json === null ? null : json["access_token"];
    if (typeof token !== "string" || token === "") {
      throw new Error(`${this.venue} issued no access token`);
    }
    return token;
  }

  private async colonyId(token: string): Promise<string> {
    const response = await this.input.http.fetch(
      new Request(`${this.input.origin}/api/v1/colonies?limit=200`, {
        headers: { accept: "application/json", authorization: `Bearer ${token}` },
      }),
    );
    const text = await response.text();
    if (!response.ok) throw refused(this.venue, response.status, text);
    let listed: unknown = null;
    try {
      listed = JSON.parse(text);
    } catch {
      listed = null;
    }
    const rows = Array.isArray(listed)
      ? listed
      : typeof listed === "object" && listed !== null && Array.isArray((listed as Record<string, unknown>)["colonies"])
        ? ((listed as Record<string, unknown>)["colonies"] as unknown[])
        : [];
    for (const row of rows) {
      if (typeof row !== "object" || row === null) continue;
      const record = row as Record<string, unknown>;
      if (record["name"] === this.input.colony) {
        const id = idOf(record, "id");
        if (id !== null) return id;
      }
    }
    throw new Error(`${this.venue} has no colony named ${this.input.colony}`);
  }

  async post(body: PostBody): Promise<Posted> {
    const token = await this.token();
    const colonyId = await this.colonyId(token);
    const response = await this.input.http.fetch(
      new Request(`${this.input.origin}/api/v1/posts`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          colony_id: colonyId,
          post_type: this.input.postType,
          title: body.title,
          body: body.body,
        }),
      }),
    );
    const { text, json } = await jsonOf(response);
    if (!response.ok) throw refused(this.venue, response.status, text);
    const id = idOf(json, "id", "post_id");
    if (id === null) throw new Error(`${this.venue} accepted the post and named no id`);
    const url = json === null ? null : json["url"];
    return {
      id,
      url: typeof url === "string" && url !== "" ? url : `${this.input.origin}/posts/${id}`,
    };
  }
}

/**
 * GitHub: one comment on the pinned issue.
 *
 * A comment and not a new issue, because the batch thread on GitHub is one
 * issue that stays open: the ask, its answers and the next batch read as one
 * conversation, which is what a thread is for. The title is not sent — an issue
 * comment has none — and is kept as the body's own first line by the composer,
 * so the same body reads the same way at every venue.
 */
export class GitHubIssuePoster implements Poster {
  readonly venue: string;

  constructor(
    private readonly input: {
      readonly venue: string;
      readonly api: string;
      /** `<owner>/<name>`, as the repository is written everywhere else. */
      readonly repository: string;
      readonly issue: number;
      /** The token, read from the named environment variable, never printed. */
      readonly token: string;
      readonly http: PosterHttp;
    },
  ) {
    this.venue = input.venue;
  }

  async post(body: PostBody): Promise<Posted> {
    const response = await this.input.http.fetch(
      new Request(
        `${this.input.api}/repos/${this.input.repository}/issues/${this.input.issue}/comments`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            accept: "application/vnd.github+json",
            authorization: `Bearer ${this.input.token}`,
            "user-agent": "nomankind-batch-post",
          },
          body: JSON.stringify({ body: body.body }),
        },
      ),
    );
    const { text, json } = await jsonOf(response);
    if (!response.ok) throw refused(this.venue, response.status, text);
    const id = idOf(json, "id");
    const url = json === null ? null : json["html_url"];
    if (id === null) throw new Error(`${this.venue} accepted the comment and named no id`);
    return {
      id,
      url:
        typeof url === "string" && url !== ""
          ? url
          : `https://github.com/${this.input.repository}/issues/${this.input.issue}`,
    };
  }
}

/**
 * GitHub through the `gh` CLI (`--via-gh`).
 *
 * The same comment on the same issue, made by the tool the maintainer is
 * already signed in to, so a run needs no token in the environment at all. The
 * body goes in on standard input rather than as an argument: a batch post is
 * thousands of characters of somebody's argv otherwise, and the shell is not a
 * place to put text this long.
 *
 * `gh` prints the comment's URL and nothing else useful, so that is what the id
 * is taken from: the trailing path segment, which is `issuecomment-<id>`.
 */
export class GitHubCliPoster implements Poster {
  readonly venue: string;

  constructor(
    private readonly input: {
      readonly venue: string;
      readonly repository: string;
      readonly issue: number;
      readonly runner: CommandRunner;
    },
  ) {
    this.venue = input.venue;
  }

  async post(body: PostBody): Promise<Posted> {
    const result = await this.input.runner.run(
      "gh",
      [
        "issue",
        "comment",
        String(this.input.issue),
        "--repo",
        this.input.repository,
        "--body-file",
        "-",
      ],
      body.body,
    );
    if (result.status !== 0) {
      throw new Error(
        `${this.venue} refused via gh (${result.status}): ${result.stderr.slice(0, REFUSAL_CHARS)}`,
      );
    }
    const url = result.stdout.trim().split(/\s+/).pop() ?? "";
    const marker = url.lastIndexOf("issuecomment-");
    return {
      id: marker === -1 ? url : url.slice(marker + "issuecomment-".length),
      url:
        url === ""
          ? `https://github.com/${this.input.repository}/issues/${this.input.issue}`
          : url,
    };
  }
}

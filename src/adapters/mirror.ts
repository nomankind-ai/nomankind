/**
 * The mirror adapter: the day's export out to a public git repository.
 *
 * Whitepaper Section 11, "Deployment and status": the log is mirrored daily to a
 * public repository under CC0. The value of that is exactly the value of the
 * anchor adapter beside it — the copy is somewhere nomankind does not run, so a
 * nomankind that stops answering does not take the record with it.
 *
 * GitHub's git data API is small and this speaks it directly: read the branch's
 * tree, read its head commit, write a tree with `base_tree` set and the changed
 * files inline, write a commit, move the ref. Six calls, no blob uploads, and
 * `base_tree` is what keeps everything outside this environment's own directory
 * — the LICENSE, the README, the other environment's export — exactly where it
 * was. Which repository and which branch is src/policy.ts's MIRROR; no address
 * is written down here.
 *
 * Never throws. Every failure is a named refusal the sweep counts and the status
 * page shows, because an export that did not happen today is a thing to say out
 * loud rather than a stack trace in a log nobody reads. The token is a Worker
 * secret (D-016): it is never logged, never returned, and never put in a
 * refusal's detail — an adapter that put a credential in an error message would
 * publish it.
 *
 * The platform fetch goes out with no receiver, for the reason every adapter
 * here does it (workerd's "Illegal invocation", the M13 lesson).
 *
 * No policy number lives here: the addresses come from MIRROR and the timeout
 * from FETCH_TIMEOUT_MS.
 */

import {
  gitBlobSha,
  mirrorDiff,
  mirrorUrls,
  type MirrorFile,
} from "../mirror.js";
import { FETCH_TIMEOUT_MS, MIRROR } from "../policy.js";

/** Which mirror track an environment runs. */
export type MirrorKind = "github" | "mock" | "unavailable";

/** What one push is asked to write. */
export interface MirrorPushInput {
  /** The repository directory this environment owns: `demo`, `production`. */
  readonly prefix: string;
  /** The files, with paths relative to `<prefix>/`. */
  readonly files: readonly MirrorFile[];
  readonly message: string;
}

/**
 * What a push answers.
 *
 * `unchanged` is a success and not a refusal: an export whose bytes are already
 * in the repository is a day that is mirrored, and writing an empty commit to
 * say so would make the history harder to read rather than more honest.
 */
export type MirrorPush =
  | {
      readonly ok: true;
      readonly commit: string;
      readonly tree: string;
      readonly changed: number;
      readonly unchanged: boolean;
      readonly url: string;
      readonly raw_url: string;
    }
  | {
      readonly ok: false;
      readonly reason: "mirror_unavailable" | "mirror_conflict" | "mirror_failed";
      /** What went wrong, in one word or a status. Never a credential. */
      readonly detail: string | null;
    };

/**
 * Where the day's export goes.
 *
 * The kernel names the shape and nothing more, exactly as the witness and anchor
 * adapters do: the implementations below do network I/O, and nothing in the
 * kernel may.
 */
export interface MirrorAdapter {
  readonly kind: MirrorKind;
  push(input: MirrorPushInput): Promise<MirrorPush>;
}

/** The User-Agent every call from this adapter carries. A wire fact, not policy. */
const USER_AGENT = "nomankind-mirror";

/** GitHub's own media type and version pin. Format constants, not policy. */
const GITHUB_ACCEPT = "application/vnd.github+json";
const GITHUB_API_VERSION = "2022-11-28";

/** The mode a plain file has in a git tree. A git constant. */
const BLOB_MODE = "100644";

const NOT_FOUND = 404;
const UNAUTHORIZED = 401;
const FORBIDDEN = 403;
const CONFLICT = 409;
const UNPROCESSABLE = 422;

/** What the adapter needs to be built. */
export interface GitHubMirrorOptions {
  /** The write credential. Never logged and never in a refusal. */
  readonly token: string;
  readonly fetch?: typeof fetch;
  readonly repository?: string;
  readonly branch?: string;
  readonly api?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** One call's answer: the parsed body, or the refusal it should become. */
type Answer =
  | { readonly ok: true; readonly body: unknown }
  | { readonly ok: false; readonly refusal: MirrorPush };

function failed(detail: string | null): MirrorPush {
  return { ok: false, reason: "mirror_failed", detail };
}

function conflict(detail: string | null): MirrorPush {
  return { ok: false, reason: "mirror_conflict", detail };
}

/**
 * The repository the export is pushed to.
 *
 * Both environments push to the same repository and branch, each under its own
 * top-level directory, which is why `base_tree` matters: a demo push must leave
 * production's directory untouched, and it does because the new tree is the old
 * one with this prefix's changed paths written over it.
 */
export class GitHubMirrorAdapter implements MirrorAdapter {
  readonly kind = "github";

  readonly #token: string;
  readonly #fetch: typeof fetch;
  readonly #repository: string;
  readonly #branch: string;
  readonly #api: string;

  constructor(options: GitHubMirrorOptions) {
    this.#token = options.token;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#repository = options.repository ?? MIRROR.repository;
    this.#branch = options.branch ?? MIRROR.branch;
    this.#api = options.api ?? MIRROR.api;
  }

  async push(input: MirrorPushInput): Promise<MirrorPush> {
    try {
      return await this.#push(input);
    } catch {
      // Nothing about the throw travels: a fetch's error can carry the request's
      // own headers, and one of ours is a bearer token.
      return failed("network");
    }
  }

  /**
   * Every call goes through here: the headers, the timeout, no receiver.
   *
   * `moving` says this call is the one that moves the branch ref, which is the
   * only place a 409 or a 422 means "somebody else pushed first" rather than
   * "that request was wrong".
   */
  async #call(
    path: string,
    init: RequestInit,
    moving = false,
  ): Promise<Answer> {
    const call = this.#fetch;
    let response: Response;
    try {
      response = await call(`${this.#api}${path}`, {
        ...init,
        headers: {
          authorization: `Bearer ${this.#token}`,
          accept: GITHUB_ACCEPT,
          "x-github-api-version": GITHUB_API_VERSION,
          "user-agent": USER_AGENT,
          ...(init.body === undefined
            ? {}
            : { "content-type": "application/json" }),
        },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch {
      return { ok: false, refusal: failed("network") };
    }

    if (!response.ok) {
      return { ok: false, refusal: this.#refusal(response.status, moving) };
    }

    try {
      return { ok: true, body: await response.json() };
    } catch {
      return { ok: false, refusal: failed("bad_response") };
    }
  }

  /** What one status means, in the words the sweep and the page use. */
  #refusal(status: number, moving: boolean): MirrorPush {
    if (status === NOT_FOUND) return failed("repository_or_branch_not_found");
    if (status === UNAUTHORIZED || status === FORBIDDEN) return failed("auth");
    if (moving && (status === CONFLICT || status === UNPROCESSABLE)) {
      // The other environment moved the branch while this export was being
      // built. Not a fault: the next run reads the tree it left and pushes on
      // top of it.
      return conflict(String(status));
    }
    return failed(String(status));
  }

  async #push(input: MirrorPushInput): Promise<MirrorPush> {
    // (1) The branch's whole tree. The branch name is accepted where a tree sha
    // goes, so this is one call rather than two.
    const tree = await this.#call(
      `/repos/${this.#repository}/git/trees/${this.#branch}?recursive=1`,
      { method: "GET" },
    );
    if (!tree.ok) return tree.refusal;
    if (!isRecord(tree.body)) return failed("bad_response");
    // A truncated tree is a tree we did not read, and diffing against half a
    // listing would rewrite files that had not changed. Named, and left for the
    // maintainer: this is the volume the layout has to be split at.
    if (tree.body["truncated"] === true) return failed("tree_truncated");

    const headTree = tree.body["sha"];
    if (typeof headTree !== "string") return failed("bad_response");

    const existing = this.#existing(tree.body["tree"], input.prefix);

    // (2) The head commit the new one is parented on.
    const ref = await this.#call(
      `/repos/${this.#repository}/git/ref/heads/${this.#branch}`,
      { method: "GET" },
    );
    if (!ref.ok) return ref.refusal;
    const head = isRecord(ref.body) && isRecord(ref.body["object"])
      ? ref.body["object"]["sha"]
      : null;
    if (typeof head !== "string") return failed("bad_response");

    // (3) What actually changed. A day that changed nothing writes nothing.
    const changed = await mirrorDiff(input.files, existing);
    if (changed.length === 0) {
      return {
        ok: true,
        commit: head,
        tree: headTree,
        changed: 0,
        unchanged: true,
        ...mirrorUrls(head, input.prefix),
      };
    }

    // (4) The new tree: the head's, with this prefix's changed files over it.
    // Inline content, so no blob call per file, and `base_tree` is what leaves
    // the LICENSE, the README and the other environment's directory alone.
    const written = await this.#call(`/repos/${this.#repository}/git/trees`, {
      method: "POST",
      body: JSON.stringify({
        base_tree: headTree,
        tree: changed.map((file) => ({
          path: `${input.prefix}/${file.path}`,
          mode: BLOB_MODE,
          type: "blob",
          content: file.content,
        })),
      }),
    });
    if (!written.ok) return written.refusal;
    const treeSha = isRecord(written.body) ? written.body["sha"] : null;
    if (typeof treeSha !== "string") return failed("bad_response");

    // (5) The commit.
    const commit = await this.#call(`/repos/${this.#repository}/git/commits`, {
      method: "POST",
      body: JSON.stringify({
        message: input.message,
        tree: treeSha,
        parents: [head],
      }),
    });
    if (!commit.ok) return commit.refusal;
    const commitSha = isRecord(commit.body) ? commit.body["sha"] : null;
    if (typeof commitSha !== "string") return failed("bad_response");

    // (6) The ref, without force: the other environment may have pushed while
    // this export was being built, and losing that race is a conflict the next
    // run repairs rather than a commit that overwrites somebody else's.
    const moved = await this.#call(
      `/repos/${this.#repository}/git/refs/heads/${this.#branch}`,
      { method: "PATCH", body: JSON.stringify({ sha: commitSha, force: false }) },
      true,
    );
    if (!moved.ok) return moved.refusal;

    return {
      ok: true,
      commit: commitSha,
      tree: treeSha,
      changed: changed.length,
      unchanged: false,
      ...mirrorUrls(commitSha, input.prefix),
    };
  }

  /**
   * The blob sha of every path already under this prefix, keyed the way
   * `mirrorDiff` asks: relative to the prefix, because the layout knows nothing
   * about where in a repository it sits.
   */
  #existing(tree: unknown, prefix: string): Map<string, string> {
    const existing = new Map<string, string>();
    if (!Array.isArray(tree)) return existing;
    const under = `${prefix}/`;
    for (const node of tree) {
      if (!isRecord(node)) continue;
      const path = node["path"];
      const sha = node["sha"];
      if (typeof path !== "string" || typeof sha !== "string") continue;
      if (node["type"] !== "blob" || !path.startsWith(under)) continue;
      existing.set(path.slice(under.length), sha);
    }
    return existing;
  }
}

/**
 * The mirror for a test and for a laptop: the files in memory, and a commit
 * counter for a sha.
 *
 * Deterministic on purpose. The shas are made from the counter rather than from
 * a digest, so nothing here can be mistaken for a real git object, and two runs
 * of the same test produce the same report.
 */
export class MockMirrorAdapter implements MirrorAdapter {
  readonly kind = "mock";

  /** Every path ever written, keyed `<prefix>/<path>`, with its content. */
  readonly files = new Map<string, string>();
  /** How many commits this mirror has taken. */
  commits = 0;

  async push(input: MirrorPushInput): Promise<MirrorPush> {
    const existing = new Map<string, string>();
    const under = `${input.prefix}/`;
    for (const [path, content] of this.files) {
      if (!path.startsWith(under)) continue;
      existing.set(path.slice(under.length), await gitBlobSha(content));
    }

    const changed = await mirrorDiff(input.files, existing);
    if (changed.length === 0) {
      const commit = this.#sha("commit");
      return {
        ok: true,
        commit,
        tree: this.#sha("tree"),
        changed: 0,
        unchanged: true,
        ...mirrorUrls(commit, input.prefix),
      };
    }

    for (const file of changed) {
      this.files.set(`${under}${file.path}`, file.content);
    }
    this.commits += 1;
    const commit = this.#sha("commit");
    return {
      ok: true,
      commit,
      tree: this.#sha("tree"),
      changed: changed.length,
      unchanged: false,
      ...mirrorUrls(commit, input.prefix),
    };
  }

  /** A fake object name: the kind, the counter, and nothing that looks real. */
  #sha(kind: string): string {
    return `mock-${kind}-${this.commits}`;
  }
}

/**
 * No token, no mirror.
 *
 * It refuses rather than pretending, exactly as the payout stub and the witness
 * adapter do on production: a mirror that answered "exported" without a
 * repository behind it would put a link on the status page that goes nowhere.
 */
export class UnavailableMirrorAdapter implements MirrorAdapter {
  readonly kind = "unavailable";

  async push(_input?: MirrorPushInput): Promise<MirrorPush> {
    return { ok: false, reason: "mirror_unavailable", detail: null };
  }
}

/**
 * Which track this environment runs (decision D-013 as amended).
 *
 * The token and not the environment name decides it: both demo and production
 * push to the same repository under their own directories, and a maintainer who
 * has not set the secret gets an environment that says so rather than one that
 * fails a call every day.
 */
export function mirrorAdapterFor(env: {
  readonly MIRROR_TOKEN?: string;
}): MirrorAdapter {
  const token = env.MIRROR_TOKEN;
  if (typeof token !== "string" || token === "") {
    return new UnavailableMirrorAdapter();
  }
  return new GitHubMirrorAdapter({ token });
}

/** The same branch, as a word: what the status page and the mirror page show. */
export function mirrorKindFor(env: {
  readonly MIRROR_TOKEN?: string;
}): MirrorKind {
  return mirrorAdapterFor(env).kind;
}

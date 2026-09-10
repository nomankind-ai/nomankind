/**
 * The mirror adapter, against a repository that exists only in this file.
 *
 * Whitepaper Section 11: the sealed log goes out daily to a public repository
 * under CC0. This is the six calls that put it there — read the tree, read the
 * head, diff, write a tree, write a commit, move the ref — and every way they
 * can refuse. Nothing here reaches the network: the fake below answers
 * GitHub-shaped bodies from a table and records what it was asked.
 *
 * The token is the thing this file watches hardest. It is a Worker secret
 * (D-016), so it must appear in exactly one place — the Authorization header —
 * and in no refusal, no return value and nothing a caller could log.
 */

import { describe, expect, it } from "vitest";

import {
  GitHubMirrorAdapter,
  MockMirrorAdapter,
  UnavailableMirrorAdapter,
  mirrorAdapterFor,
  mirrorKindFor,
  type MirrorPush,
} from "../src/adapters/mirror.js";
import { gitBlobSha, type MirrorFile } from "../src/mirror.js";
import { MIRROR } from "../src/policy.js";

const TOKEN = "ghp_this_is_the_secret_and_must_never_leak";
const API = "https://api.test";
const REPOSITORY = "nomankind-ai/log-test";
const BRANCH = "trunk";
const PREFIX = "demo";

const FILES: readonly MirrorFile[] = Object.freeze([
  { path: "index.json", content: "[]\n" },
  { path: "mirror.json", content: '{\n  "format": "nomankind-mirror-v1"\n}\n' },
]);

const MESSAGE = "mirror demo 2026-09-11: head 42, seal 3";

const HEAD_TREE = "tree-at-head";
const HEAD_COMMIT = "commit-at-head";
const NEW_TREE = "tree-just-written";
const NEW_COMMIT = "commit-just-written";

interface Call {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: unknown;
}

/** One canned answer: a status, and a JSON body when it has one. */
interface Answer {
  readonly status: number;
  readonly body?: unknown;
}

/** The four paths a push walks, spelt once. */
const TREES = `${API}/repos/${REPOSITORY}/git/trees/${BRANCH}?recursive=1`;
const REF = `${API}/repos/${REPOSITORY}/git/ref/heads/${BRANCH}`;
const WRITE_TREE = `${API}/repos/${REPOSITORY}/git/trees`;
const WRITE_COMMIT = `${API}/repos/${REPOSITORY}/git/commits`;
const MOVE_REF = `${API}/repos/${REPOSITORY}/git/refs/heads/${BRANCH}`;

/** A repository table: each url answers a status and a body. */
function repository(table: Record<string, Answer>): {
  fetch: typeof fetch;
  calls: Call[];
} {
  const calls: Call[] = [];
  const fetchFn = async function (
    this: unknown,
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    // workerd throws exactly this when a platform fetch is called on anything
    // but the global object, and Node's does not (the M13 lesson).
    if (this !== undefined && this !== globalThis) {
      throw new TypeError("Illegal invocation");
    }
    const url = String(input);
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(
      (init?.headers ?? {}) as Record<string, string>,
    )) {
      headers[name.toLowerCase()] = value;
    }
    calls.push({
      url,
      method: init?.method ?? "GET",
      headers,
      body:
        typeof init?.body === "string" ? JSON.parse(init.body) : null,
    });

    const answer = table[url];
    if (answer === undefined) throw new TypeError(`unroutable: ${url}`);
    return new Response(
      answer.body === undefined ? "" : JSON.stringify(answer.body),
      { status: answer.status, headers: { "content-type": "application/json" } },
    );
  } as unknown as typeof fetch;
  return { fetch: fetchFn, calls };
}

/** A tree listing that already holds `files` under the prefix. */
async function treeHolding(
  files: readonly MirrorFile[],
  extra: readonly { path: string; sha: string }[] = [],
): Promise<{ sha: string; truncated: boolean; tree: unknown[] }> {
  const tree: unknown[] = [];
  for (const file of files) {
    tree.push({
      path: `${PREFIX}/${file.path}`,
      type: "blob",
      sha: await gitBlobSha(file.content),
    });
  }
  for (const one of extra) {
    tree.push({ path: one.path, type: "blob", sha: one.sha });
  }
  return { sha: HEAD_TREE, truncated: false, tree };
}

/** The full happy table, with whatever the caller wants overridden. */
async function happy(over: Record<string, Answer> = {}): Promise<
  Record<string, Answer>
> {
  return {
    [TREES]: {
      status: 200,
      body: await treeHolding([], [{ path: "LICENSE", sha: "license-sha" }]),
    },
    [REF]: { status: 200, body: { object: { sha: HEAD_COMMIT } } },
    [WRITE_TREE]: { status: 201, body: { sha: NEW_TREE } },
    [WRITE_COMMIT]: { status: 201, body: { sha: NEW_COMMIT } },
    [MOVE_REF]: { status: 200, body: { object: { sha: NEW_COMMIT } } },
    ...over,
  };
}

function adapter(fetchFn: typeof fetch): GitHubMirrorAdapter {
  return new GitHubMirrorAdapter({
    token: TOKEN,
    fetch: fetchFn,
    repository: REPOSITORY,
    branch: BRANCH,
    api: API,
  });
}

function push(fetchFn: typeof fetch): Promise<MirrorPush> {
  return adapter(fetchFn).push({ prefix: PREFIX, files: FILES, message: MESSAGE });
}

/** Every string anywhere in a value, for the token hunt. */
function stringsIn(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringsIn);
  if (typeof value === "object" && value !== null) {
    return Object.entries(value).flatMap(([key, one]) => [key, ...stringsIn(one)]);
  }
  return [];
}

describe("the GitHub mirror", () => {
  it("walks the six calls in order and answers where the export landed", async () => {
    const { fetch, calls } = repository(await happy());
    const answer = await push(fetch);

    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `GET ${TREES}`,
      `GET ${REF}`,
      `POST ${WRITE_TREE}`,
      `POST ${WRITE_COMMIT}`,
      `PATCH ${MOVE_REF}`,
    ]);
    expect(answer).toEqual({
      ok: true,
      commit: NEW_COMMIT,
      tree: NEW_TREE,
      changed: FILES.length,
      unchanged: false,
      url: `${MIRROR.web}/${MIRROR.repository}/tree/${NEW_COMMIT}/${PREFIX}`,
      raw_url: `${MIRROR.raw}/${MIRROR.repository}/${NEW_COMMIT}/${PREFIX}/mirror.json`,
    });
  });

  it("writes the files inline under the prefix, on top of the head tree", async () => {
    const { fetch, calls } = repository(await happy());
    await push(fetch);
    const written = calls.find((call) => call.url === WRITE_TREE)!
      .body as Record<string, unknown>;
    // base_tree is what leaves the LICENSE, the README and the other
    // environment's directory exactly where they were.
    expect(written["base_tree"]).toBe(HEAD_TREE);
    expect(written["tree"]).toEqual(
      FILES.map((file) => ({
        path: `${PREFIX}/${file.path}`,
        mode: "100644",
        type: "blob",
        content: file.content,
      })),
    );
  });

  it("parents the commit on the head and moves the ref without force", async () => {
    const { fetch, calls } = repository(await happy());
    await push(fetch);
    expect(calls.find((call) => call.url === WRITE_COMMIT)!.body).toEqual({
      message: MESSAGE,
      tree: NEW_TREE,
      parents: [HEAD_COMMIT],
    });
    expect(calls.find((call) => call.url === MOVE_REF)!.body).toEqual({
      sha: NEW_COMMIT,
      force: false,
    });
  });

  it("carries the same headers on every call, and the token only there", async () => {
    const { fetch, calls } = repository(await happy());
    await push(fetch);
    for (const call of calls) {
      expect([call.url, call.headers["authorization"]]).toEqual([
        call.url,
        `Bearer ${TOKEN}`,
      ]);
      expect([call.url, call.headers["accept"]]).toEqual([
        call.url,
        "application/vnd.github+json",
      ]);
      expect([call.url, call.headers["x-github-api-version"]]).toEqual([
        call.url,
        "2022-11-28",
      ]);
      expect([call.url, call.headers["user-agent"]]).toEqual([
        call.url,
        "nomankind-mirror",
      ]);
    }
    for (const call of calls.filter((one) => one.body !== null)) {
      expect(call.headers["content-type"]).toBe("application/json");
    }
  });

  it("writes nothing at all when the repository already holds these bytes", async () => {
    const { fetch, calls } = repository(
      await happy({ [TREES]: { status: 200, body: await treeHolding(FILES) } }),
    );
    const answer = await push(fetch);
    expect(answer).toEqual({
      ok: true,
      commit: HEAD_COMMIT,
      tree: HEAD_TREE,
      changed: 0,
      unchanged: true,
      url: `${MIRROR.web}/${MIRROR.repository}/tree/${HEAD_COMMIT}/${PREFIX}`,
      raw_url: `${MIRROR.raw}/${MIRROR.repository}/${HEAD_COMMIT}/${PREFIX}/mirror.json`,
    });
    // Two reads and nothing else: an unchanged day costs no commit.
    expect(calls.map((call) => call.url)).toEqual([TREES, REF]);
  });

  it("pushes only the files that changed", async () => {
    const { fetch, calls } = repository(
      await happy({
        [TREES]: {
          status: 200,
          body: await treeHolding([FILES[0]!]),
        },
      }),
    );
    const answer = await push(fetch);
    expect(answer).toMatchObject({ ok: true, changed: 1, unchanged: false });
    const written = calls.find((call) => call.url === WRITE_TREE)!
      .body as { tree: { path: string }[] };
    expect(written.tree.map((one) => one.path)).toEqual([`${PREFIX}/mirror.json`]);
  });

  it("reads a path's sha only under its own prefix", async () => {
    // The other environment's identical file must not be mistaken for ours.
    const { fetch } = repository(
      await happy({
        [TREES]: {
          status: 200,
          body: {
            sha: HEAD_TREE,
            truncated: false,
            tree: await Promise.all(
              FILES.map(async (file) => ({
                path: `production/${file.path}`,
                type: "blob",
                sha: await gitBlobSha(file.content),
              })),
            ),
          },
        },
      }),
    );
    expect(await push(fetch)).toMatchObject({ ok: true, changed: FILES.length });
  });

  it("refuses a truncated tree rather than diffing against half a listing", async () => {
    const { fetch, calls } = repository(
      await happy({
        [TREES]: { status: 200, body: { sha: HEAD_TREE, truncated: true, tree: [] } },
      }),
    );
    expect(await push(fetch)).toEqual({
      ok: false,
      reason: "mirror_failed",
      detail: "tree_truncated",
    });
    expect(calls).toHaveLength(1);
  });

  it("names a missing repository or branch, and stops", async () => {
    const { fetch, calls } = repository(
      await happy({ [TREES]: { status: 404, body: { message: "Not Found" } } }),
    );
    expect(await push(fetch)).toEqual({
      ok: false,
      reason: "mirror_failed",
      detail: "repository_or_branch_not_found",
    });
    expect(calls).toHaveLength(1);
  });

  it("names an auth failure in one word, on either status", async () => {
    for (const status of [401, 403]) {
      const { fetch } = repository(await happy({ [TREES]: { status } }));
      expect(await push(fetch)).toEqual({
        ok: false,
        reason: "mirror_failed",
        detail: "auth",
      });
    }
  });

  it("calls a lost race for the branch a conflict, not a failure", async () => {
    for (const status of [409, 422]) {
      const { fetch, calls } = repository(
        await happy({ [MOVE_REF]: { status, body: { message: "not a fast forward" } } }),
      );
      expect(await push(fetch)).toEqual({
        ok: false,
        reason: "mirror_conflict",
        detail: String(status),
      });
      // The other five happened: the conflict is at the ref and nowhere else.
      expect(calls).toHaveLength(5);
    }
  });

  it("calls a bad write a failure and never a conflict", async () => {
    // 422 anywhere but the ref move is a request that was wrong, not a race.
    const { fetch } = repository(await happy({ [WRITE_TREE]: { status: 422 } }));
    expect(await push(fetch)).toEqual({
      ok: false,
      reason: "mirror_failed",
      detail: "422",
    });
  });

  it("names any other status by its number", async () => {
    const { fetch } = repository(await happy({ [REF]: { status: 500 } }));
    expect(await push(fetch)).toEqual({
      ok: false,
      reason: "mirror_failed",
      detail: "500",
    });
  });

  it("answers network when the call throws, and never throws itself", async () => {
    const exploding = (() => {
      throw new TypeError(`fetch failed with authorization: Bearer ${TOKEN}`);
    }) as unknown as typeof fetch;
    expect(await push(exploding)).toEqual({
      ok: false,
      reason: "mirror_failed",
      detail: "network",
    });
  });

  it("never puts the token in anything it answers", async () => {
    const tables: Record<string, Answer>[] = [
      await happy(),
      await happy({ [TREES]: { status: 403 } }),
      await happy({ [TREES]: { status: 404 } }),
      await happy({ [MOVE_REF]: { status: 409 } }),
      await happy({ [REF]: { status: 500 } }),
      await happy({
        [TREES]: { status: 200, body: { sha: HEAD_TREE, truncated: true, tree: [] } },
      }),
    ];
    for (const table of tables) {
      const { fetch } = repository(table);
      const answer = await push(fetch);
      for (const found of stringsIn(answer)) {
        expect([found, found.includes(TOKEN)]).toEqual([found, false]);
      }
    }
    // The throwing fetch too, whose own message carries it.
    const exploding = (() => {
      throw new TypeError(`boom ${TOKEN}`);
    }) as unknown as typeof fetch;
    for (const found of stringsIn(await push(exploding))) {
      expect(found.includes(TOKEN)).toBe(false);
    }
  });

  it("never calls fetch with the adapter itself as the receiver", async () => {
    // The fake above throws "Illegal invocation" on a bound receiver, so an
    // answer coming back at all is the check.
    const { fetch } = repository(await happy());
    expect(await push(fetch)).toMatchObject({ ok: true });
  });

  it("defaults the repository, the branch and the api to policy's", async () => {
    const calls: string[] = [];
    const fetchFn = (async (input: string | URL | Request) => {
      calls.push(String(input));
      return new Response("", { status: 500 });
    }) as unknown as typeof fetch;
    await new GitHubMirrorAdapter({ token: TOKEN, fetch: fetchFn }).push({
      prefix: PREFIX,
      files: FILES,
      message: MESSAGE,
    });
    expect(calls[0]).toBe(
      `${MIRROR.api}/repos/${MIRROR.repository}/git/trees/${MIRROR.branch}?recursive=1`,
    );
  });
});

describe("the mock mirror", () => {
  it("keeps the files, counts the commits, and repeats itself", async () => {
    const mock = new MockMirrorAdapter();
    const first = await mock.push({ prefix: PREFIX, files: FILES, message: MESSAGE });
    expect(first).toMatchObject({ ok: true, changed: 2, unchanged: false });
    expect(mock.commits).toBe(1);
    expect(mock.files.get(`${PREFIX}/index.json`)).toBe("[]\n");

    const second = await mock.push({ prefix: PREFIX, files: FILES, message: MESSAGE });
    expect(second).toMatchObject({ ok: true, changed: 0, unchanged: true });
    expect(mock.commits).toBe(1);
  });

  it("pushes only what changed, and leaves the other prefix alone", async () => {
    const mock = new MockMirrorAdapter();
    await mock.push({ prefix: "production", files: FILES, message: MESSAGE });
    await mock.push({ prefix: PREFIX, files: FILES, message: MESSAGE });
    const changed = await mock.push({
      prefix: PREFIX,
      files: [FILES[0]!, { path: "mirror.json", content: "{}\n" }],
      message: MESSAGE,
    });
    expect(changed).toMatchObject({ ok: true, changed: 1 });
    expect(mock.files.get("production/mirror.json")).toBe(FILES[1]!.content);
  });
});

describe("which track an environment runs", () => {
  it("mirrors when the secret is set, and says so", () => {
    expect(mirrorKindFor({ MIRROR_TOKEN: TOKEN })).toBe("github");
    expect(mirrorAdapterFor({ MIRROR_TOKEN: TOKEN })).toBeInstanceOf(
      GitHubMirrorAdapter,
    );
  });

  it("is unavailable with no secret, or an empty one", () => {
    for (const env of [{}, { MIRROR_TOKEN: "" }]) {
      expect(mirrorKindFor(env)).toBe("unavailable");
      expect(mirrorAdapterFor(env)).toBeInstanceOf(UnavailableMirrorAdapter);
    }
  });

  it("refuses rather than pretending when it is unavailable", async () => {
    expect(await new UnavailableMirrorAdapter().push()).toEqual({
      ok: false,
      reason: "mirror_unavailable",
      detail: null,
    });
  });
});

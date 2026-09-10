/**
 * The mirror's other credential: a GitHub App, and the token it mints per push.
 *
 * The token the adapter shipped with expires, and a daily export that stops
 * because nobody renewed a secret is an outage with nothing wrong behind it. An
 * App's private key does not expire: it signs a JWT, the JWT buys an
 * installation token good for an hour, and that token pushes. This file is the
 * whole of that — the DER wrapper WebCrypto needs, the three shapes a pasted
 * PEM arrives in, the JWT checked against the key's own public half, the two
 * minting calls and every way they refuse, and the eight calls one App push
 * makes.
 *
 * Nothing here reaches the network, and the two secrets are what it watches
 * hardest: the private key and the minted token must appear in exactly one
 * header each and in no refusal, no return value and nothing a caller could
 * log.
 */

import { describe, expect, it, vi } from "vitest";

import {
  GitHubMirrorAdapter,
  UnavailableMirrorAdapter,
  appJwt,
  installationToken,
  mirrorAdapterFor,
  mirrorKindFor,
  pkcs1ToPkcs8,
  type GitHubAppCredentials,
} from "../src/adapters/mirror.js";
import { base64Encode, base64urlDecode } from "../src/encoding.js";
import { gitBlobSha, type MirrorFile } from "../src/mirror.js";
import { MIRROR } from "../src/policy.js";

const APP_ID = "1234567";
const API = "https://api.test";
const REPOSITORY = "nomankind-ai/log-test";
const BRANCH = "trunk";
const PREFIX = "demo";
const INSTALLATION = 987654;
const MINTED = "ghs_the_minted_token_and_it_must_never_leak";
/** The environment's fallback credential: set, and never the one that pushes. */
const ENV_TOKEN = "ghp_the_environment_token_and_the_App_wins_over_it";
const EXPIRES_AT = "2026-09-11T01:00:00Z";
const NOW = new Date("2026-09-11T00:05:00.000Z");

const FILES: readonly MirrorFile[] = Object.freeze([
  { path: "index.json", content: "[]\n" },
  { path: "mirror.json", content: '{\n  "format": "nomankind-mirror-v1"\n}\n' },
]);
const MESSAGE = "mirror demo 2026-09-11: head 42, seal 3";

const HEAD_TREE = "tree-at-head";
const HEAD_COMMIT = "commit-at-head";
const NEW_TREE = "tree-just-written";
const NEW_COMMIT = "commit-just-written";

const INSTALLATION_URL = `${API}/repos/${REPOSITORY}/installation`;
const MINT_URL = `${API}/app/installations/${INSTALLATION}/access_tokens`;
const TREES = `${API}/repos/${REPOSITORY}/git/trees/${BRANCH}?recursive=1`;
const REF = `${API}/repos/${REPOSITORY}/git/ref/heads/${BRANCH}`;
const WRITE_TREE = `${API}/repos/${REPOSITORY}/git/trees`;
const WRITE_COMMIT = `${API}/repos/${REPOSITORY}/git/commits`;
const MOVE_REF = `${API}/repos/${REPOSITORY}/git/refs/heads/${BRANCH}`;

/*
 * The same eight, at the addresses an adapter built off the environment uses:
 * `mirrorAdapterFor` takes policy's repository, branch and API, so a push made
 * through it can only be watched at policy's own urls.
 */
const ENV_INSTALLATION_URL = `${MIRROR.api}/repos/${MIRROR.repository}/installation`;
const ENV_MINT_URL = `${MIRROR.api}/app/installations/${INSTALLATION}/access_tokens`;
const ENV_TREES = `${MIRROR.api}/repos/${MIRROR.repository}/git/trees/${MIRROR.branch}?recursive=1`;
const ENV_REF = `${MIRROR.api}/repos/${MIRROR.repository}/git/ref/heads/${MIRROR.branch}`;
const ENV_WRITE_TREE = `${MIRROR.api}/repos/${MIRROR.repository}/git/trees`;
const ENV_WRITE_COMMIT = `${MIRROR.api}/repos/${MIRROR.repository}/git/commits`;
const ENV_MOVE_REF = `${MIRROR.api}/repos/${MIRROR.repository}/git/refs/heads/${MIRROR.branch}`;

const encoder = new TextEncoder();

/* One key, generated once and shared: 2048 bits costs real time. */

interface Key {
  readonly publicKey: CryptoKey;
  readonly privateKey: CryptoKey;
  /** The key as WebCrypto exports it. */
  readonly pkcs8: Uint8Array;
  /** The same key as GitHub hands it over: the inner RSAPrivateKey. */
  readonly pkcs1: Uint8Array;
}

const RSA = {
  name: "RSASSA-PKCS1-v1_5",
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: "SHA-256",
} as const;

/**
 * The DER element at `offset`: its tag, where its content starts and ends.
 *
 * A reader rather than the writer under test, so the round trip below is
 * checked against something that parses lengths independently of the code that
 * wrote them.
 */
function derRead(
  der: Uint8Array,
  offset: number,
): { tag: number; start: number; end: number } {
  const tag = der[offset]!;
  let length = der[offset + 1]!;
  let start = offset + 2;
  if (length >= 0x80) {
    const count = length - 0x80;
    length = 0;
    for (let index = 0; index < count; index += 1) {
      length = length * 256 + der[start + index]!;
    }
    start += count;
  }
  return { tag, start, end: start + length };
}

/**
 * The PKCS#1 RSAPrivateKey inside a PKCS#8 PrivateKeyInfo: the OCTET STRING
 * after the version and the algorithm. This is how the test gets hold of the
 * form GitHub downloads without shipping a private key in the repository.
 */
function pkcs1From(pkcs8: Uint8Array): Uint8Array {
  const outer = derRead(pkcs8, 0);
  expect(outer.tag).toBe(0x30);
  const version = derRead(pkcs8, outer.start);
  expect(version.tag).toBe(0x02);
  const algorithm = derRead(pkcs8, version.end);
  expect(algorithm.tag).toBe(0x30);
  const key = derRead(pkcs8, algorithm.end);
  expect(key.tag).toBe(0x04);
  return pkcs8.slice(key.start, key.end);
}

let generated: Promise<Key> | null = null;

function key(): Promise<Key> {
  generated ??= (async () => {
    const pair = (await globalThis.crypto.subtle.generateKey(RSA, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const pkcs8 = new Uint8Array(
      await globalThis.crypto.subtle.exportKey("pkcs8", pair.privateKey),
    );
    return {
      publicKey: pair.publicKey,
      privateKey: pair.privateKey,
      pkcs8,
      pkcs1: pkcs1From(pkcs8),
    };
  })();
  return generated;
}

/** A PEM, wrapped at 64 characters the way every tool writes one. */
function pem(label: string, der: Uint8Array): string {
  const body = base64Encode(der).replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

async function credentials(): Promise<GitHubAppCredentials> {
  return { app_id: APP_ID, private_key: pem("RSA PRIVATE KEY", (await key()).pkcs1) };
}

interface Call {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: unknown;
}

interface Answer {
  readonly status: number;
  readonly body?: unknown;
  /** A body sent exactly as written, for the answers that are not JSON. */
  readonly text?: string;
}

/** A GitHub that exists only in this file: a table of urls to answers. */
function github(table: Record<string, Answer>): {
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
      body: typeof init?.body === "string" ? JSON.parse(init.body) : null,
    });
    const answer = table[url];
    if (answer === undefined) throw new TypeError(`unroutable: ${url}`);
    return new Response(
      answer.text ??
        (answer.body === undefined ? "" : JSON.stringify(answer.body)),
      { status: answer.status, headers: { "content-type": "application/json" } },
    );
  } as unknown as typeof fetch;
  return { fetch: fetchFn, calls };
}

/** The two minting answers, with whatever the caller wants overridden. */
function minting(over: Record<string, Answer> = {}): Record<string, Answer> {
  return {
    [INSTALLATION_URL]: { status: 200, body: { id: INSTALLATION } },
    [MINT_URL]: {
      status: 201,
      body: { token: MINTED, expires_at: EXPIRES_AT, permissions: { contents: "write" } },
    },
    ...over,
  };
}

/** The minting pair plus the six calls of a push. */
async function whole(over: Record<string, Answer> = {}): Promise<
  Record<string, Answer>
> {
  const tree: unknown[] = [{ path: "LICENSE", type: "blob", sha: "license-sha" }];
  return {
    ...minting(),
    [TREES]: { status: 200, body: { sha: HEAD_TREE, truncated: false, tree } },
    [REF]: { status: 200, body: { object: { sha: HEAD_COMMIT } } },
    [WRITE_TREE]: { status: 201, body: { sha: NEW_TREE } },
    [WRITE_COMMIT]: { status: 201, body: { sha: NEW_COMMIT } },
    [MOVE_REF]: { status: 200, body: { object: { sha: NEW_COMMIT } } },
    ...over,
  };
}

/** The same table as `whole`, at policy's addresses. */
function envWhole(): Record<string, Answer> {
  const tree: unknown[] = [{ path: "LICENSE", type: "blob", sha: "license-sha" }];
  return {
    [ENV_INSTALLATION_URL]: { status: 200, body: { id: INSTALLATION } },
    [ENV_MINT_URL]: {
      status: 201,
      body: { token: MINTED, expires_at: EXPIRES_AT },
    },
    [ENV_TREES]: { status: 200, body: { sha: HEAD_TREE, truncated: false, tree } },
    [ENV_REF]: { status: 200, body: { object: { sha: HEAD_COMMIT } } },
    [ENV_WRITE_TREE]: { status: 201, body: { sha: NEW_TREE } },
    [ENV_WRITE_COMMIT]: { status: 201, body: { sha: NEW_COMMIT } },
    [ENV_MOVE_REF]: { status: 200, body: { object: { sha: NEW_COMMIT } } },
  };
}

/**
 * One push made by an adapter that `mirrorAdapterFor` built, watched.
 *
 * The adapter takes the platform fetch in its constructor, so the fake has to
 * be the platform fetch by the time the environment is read — which is the only
 * way to see which credential an environment actually pushes with.
 */
async function pushFromEnv(
  env: Parameters<typeof mirrorAdapterFor>[0],
): Promise<{ adapter: ReturnType<typeof mirrorAdapterFor>; calls: Call[] }> {
  const { fetch: fake, calls } = github(envWhole());
  vi.stubGlobal("fetch", fake);
  try {
    const adapter = mirrorAdapterFor(env);
    await adapter.push({ prefix: PREFIX, files: FILES, message: MESSAGE });
    return { adapter, calls };
  } finally {
    vi.unstubAllGlobals();
  }
}

async function appAdapter(fetchFn: typeof fetch): Promise<GitHubMirrorAdapter> {
  return new GitHubMirrorAdapter({
    app: await credentials(),
    fetch: fetchFn,
    repository: REPOSITORY,
    branch: BRANCH,
    api: API,
    now: () => NOW,
  });
}

/** Every string anywhere in a value, for the credential hunt. */
function stringsIn(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringsIn);
  if (typeof value === "object" && value !== null) {
    return Object.entries(value).flatMap(([name, one]) => [name, ...stringsIn(one)]);
  }
  return [];
}

/**
 * The JWT the adapter actually put on the wire, off the fake's own record.
 *
 * Read from the call rather than recomputed, so the leak hunt below is looking
 * for the exact string that was sent and not for one that merely matches.
 */
function sentJwt(calls: readonly Call[], url: string): string {
  const minting = calls.find((call) => call.url === url);
  expect(minting).toBeDefined();
  const bearer = minting!.headers["authorization"] ?? "";
  expect(bearer.startsWith("Bearer ")).toBe(true);
  const jwt = bearer.slice("Bearer ".length);
  expect(jwt.split(".")).toHaveLength(3);
  return jwt;
}

function segment(jwt: string, index: number): unknown {
  return JSON.parse(new TextDecoder().decode(base64urlDecode(jwt.split(".")[index]!)));
}

describe("wrapping a PKCS#1 key as PKCS#8", () => {
  it("writes the structure WebCrypto reads, for a short body", () => {
    // SEQUENCE { INTEGER 0, SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING }
    expect([...pkcs1ToPkcs8(Uint8Array.of(1, 2, 3))]).toEqual([
      0x30, 0x17,
      0x02, 0x01, 0x00,
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
      0x01, 0x05, 0x00,
      0x04, 0x03, 1, 2, 3,
    ]);
  });

  it("encodes a length no single byte could hold", async () => {
    // A 2048-bit key's DER is over a kilobyte, so both the outer sequence and
    // the octet string are written in DER's long form here.
    const { pkcs1 } = await key();
    const wrapped = pkcs1ToPkcs8(pkcs1);
    const outer = derRead(wrapped, 0);
    expect(wrapped[1]! >= 0x80).toBe(true);
    expect(outer.end).toBe(wrapped.length);
    const version = derRead(wrapped, outer.start);
    const algorithm = derRead(wrapped, version.end);
    const inner = derRead(wrapped, algorithm.end);
    expect([...wrapped.slice(inner.start, inner.end)]).toEqual([...pkcs1]);
  });

  it("round trips: the wrapped key imports and signs exactly as the original", async () => {
    const { pkcs1, privateKey, publicKey } = await key();
    const imported = await globalThis.crypto.subtle.importKey(
      "pkcs8",
      pkcs1ToPkcs8(pkcs1) as unknown as BufferSource,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const bytes = encoder.encode("the day's export");
    const fromWrapped = new Uint8Array(
      await globalThis.crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        imported,
        bytes as unknown as BufferSource,
      ),
    );
    const fromOriginal = new Uint8Array(
      await globalThis.crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        privateKey,
        bytes as unknown as BufferSource,
      ),
    );
    // RSASSA-PKCS1-v1_5 is deterministic, so the same key signs the same bytes
    // the same way: the wrapper carried the key and not merely something that
    // parses.
    expect([...fromWrapped]).toEqual([...fromOriginal]);
    expect(
      await globalThis.crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        publicKey,
        fromWrapped as unknown as BufferSource,
        bytes as unknown as BufferSource,
      ),
    ).toBe(true);
  });
});

describe("the pasted PEM", () => {
  it("reads all three shapes a key arrives in, and the same key each time", async () => {
    const { pkcs1 } = await key();
    const file = pem("RSA PRIVATE KEY", pkcs1);
    const shapes = [
      file,
      // A dashboard field that keeps one line.
      file.replaceAll("\n", ""),
      // A shell or a JSON blob that spelt the newlines.
      file.replaceAll("\n", "\\n"),
    ];
    const jwts = await Promise.all(
      shapes.map((shape) => appJwt({ app_id: APP_ID, private_key: shape }, NOW)),
    );
    for (const jwt of jwts) expect(jwt).toBe(jwts[0]);
    expect(segment(jwts[0]!, 1)).toMatchObject({ iss: APP_ID });
  });

  it("reads a PKCS#8 PEM too, and makes the same JWT as the PKCS#1 one", async () => {
    const { pkcs1, pkcs8 } = await key();
    expect(
      await appJwt({ app_id: APP_ID, private_key: pem("PRIVATE KEY", pkcs8) }, NOW),
    ).toBe(
      await appJwt({ app_id: APP_ID, private_key: pem("RSA PRIVATE KEY", pkcs1) }, NOW),
    );
  });
});

describe("the App JWT", () => {
  it("carries the header, the claims and a signature the public half checks", async () => {
    const jwt = await appJwt(await credentials(), NOW);
    const seconds = Math.floor(NOW.getTime() / 1000);
    expect(segment(jwt, 0)).toEqual({ alg: "RS256", typ: "JWT" });
    expect(segment(jwt, 1)).toEqual({
      iat: seconds - 60,
      exp: seconds + 9 * 60,
      iss: APP_ID,
    });

    const [header, claims, signature] = jwt.split(".");
    expect(
      await globalThis.crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        (await key()).publicKey,
        base64urlDecode(signature!) as unknown as BufferSource,
        encoder.encode(`${header}.${claims}`) as unknown as BufferSource,
      ),
    ).toBe(true);
  });

  it("is unpadded base64url in all three segments", async () => {
    const jwt = await appJwt(await credentials(), NOW);
    expect(jwt.split(".")).toHaveLength(3);
    for (const part of jwt.split(".")) {
      expect([part, /^[A-Za-z0-9_-]+$/.test(part)]).toEqual([part, true]);
    }
  });

  it("reads the clock it is handed and never one of its own", async () => {
    const later = new Date(NOW.getTime() + 3_600_000);
    const claims = segment(await appJwt(await credentials(), later), 1) as {
      iat: number;
    };
    expect(claims.iat).toBe(Math.floor(later.getTime() / 1000) - 60);
  });
});

describe("minting an installation token", () => {
  async function mint(
    fetchFn: typeof fetch,
  ): Promise<Awaited<ReturnType<typeof installationToken>>> {
    return installationToken(await credentials(), {
      fetch: fetchFn,
      repository: REPOSITORY,
      api: API,
      now: NOW,
    });
  }

  it("finds the installation, then asks for a token scoped to the one repository", async () => {
    const { fetch, calls } = github(minting());
    expect(await mint(fetch)).toEqual({
      ok: true,
      token: MINTED,
      expires_at: EXPIRES_AT,
    });
    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `GET ${INSTALLATION_URL}`,
      `POST ${MINT_URL}`,
    ]);
    expect(calls[1]!.body).toEqual({
      repositories: ["log-test"],
      permissions: { contents: "write" },
    });
  });

  it("carries the JWT as the bearer, and GitHub's own headers with it", async () => {
    const { fetch, calls } = github(minting());
    await mint(fetch);
    const jwt = await appJwt(await credentials(), NOW);
    for (const call of calls) {
      expect([call.url, call.headers["authorization"]]).toEqual([
        call.url,
        `Bearer ${jwt}`,
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
    expect(calls[1]!.headers["content-type"]).toBe("application/json");
  });

  it("names an App nobody installed on the repository, and stops", async () => {
    const { fetch, calls } = github(
      minting({ [INSTALLATION_URL]: { status: 404, body: { message: "Not Found" } } }),
    );
    expect(await mint(fetch)).toEqual({
      ok: false,
      reason: "mirror_failed",
      detail: "app_not_installed",
    });
    expect(calls).toHaveLength(1);
  });

  it("names a key GitHub would not accept in one word, on either call", async () => {
    const halves: Record<string, Answer>[] = [
      { [INSTALLATION_URL]: { status: 401 } },
      { [MINT_URL]: { status: 401 } },
    ];
    for (const over of halves) {
      const { fetch } = github(minting(over));
      expect(await mint(fetch)).toEqual({
        ok: false,
        reason: "mirror_failed",
        detail: "app_auth",
      });
    }
  });

  it("names any other status by its number, and a throw network", async () => {
    const { fetch } = github(minting({ [MINT_URL]: { status: 500 } }));
    expect(await mint(fetch)).toEqual({
      ok: false,
      reason: "mirror_failed",
      detail: "500",
    });

    const exploding = (() => {
      throw new TypeError("boom");
    }) as unknown as typeof fetch;
    expect(await mint(exploding)).toEqual({
      ok: false,
      reason: "mirror_failed",
      detail: "network",
    });
  });

  it("refuses a body that is not the answer it asked for", async () => {
    const wrong: Record<string, Answer>[] = [
      { [INSTALLATION_URL]: { status: 200, body: { message: "hello" } } },
      { [MINT_URL]: { status: 201, body: { token: MINTED } } },
    ];
    for (const over of wrong) {
      const { fetch } = github(minting(over));
      expect(await mint(fetch)).toEqual({
        ok: false,
        reason: "mirror_failed",
        detail: "bad_response",
      });
    }
  });

  it("refuses a body that did not parse at all, on either call", async () => {
    // The answer above is JSON that is missing a field; this one is not JSON:
    // a proxy's HTML, or a truncated response. Both are `bad_response`, and
    // neither may become a throw out of the minting call.
    const unparseable: Record<string, Answer>[] = [
      {
        [INSTALLATION_URL]: {
          status: 200,
          text: "<!doctype html>\n<html>rate limited</html>\n",
        },
      },
      { [MINT_URL]: { status: 201, text: "not json either" } },
    ];
    for (const over of unparseable) {
      const { fetch } = github(minting(over));
      expect(await mint(fetch)).toEqual({
        ok: false,
        reason: "mirror_failed",
        detail: "bad_response",
      });
    }
  });

  it("names a key that is not a key, without saying anything about it", async () => {
    const { fetch, calls } = github(minting());
    const answer = await installationToken(
      { app_id: APP_ID, private_key: "-----BEGIN RSA PRIVATE KEY-----\nbm90IGEga2V5\n-----END RSA PRIVATE KEY-----\n" },
      { fetch, repository: REPOSITORY, api: API, now: NOW },
    );
    expect(answer).toEqual({
      ok: false,
      reason: "mirror_failed",
      detail: "app_key",
    });
    // Nothing was asked of GitHub: the key never became a JWT.
    expect(calls).toHaveLength(0);
  });

  it("never puts the key, the JWT or the minted token in anything it answers", async () => {
    const { private_key } = await credentials();
    const tables = [
      minting(),
      minting({ [INSTALLATION_URL]: { status: 404 } }),
      minting({ [INSTALLATION_URL]: { status: 401 } }),
      minting({ [INSTALLATION_URL]: { status: 200, text: "not json" } }),
      minting({ [MINT_URL]: { status: 500 } }),
      minting({ [MINT_URL]: { status: 201, body: { token: MINTED } } }),
    ];
    for (const table of tables) {
      const { fetch, calls } = github(table);
      const answer = await mint(fetch);
      // The JWT is a credential for the whole nine minutes it lives: it buys a
      // write token, so it belongs in the header and in nothing else.
      const jwt = sentJwt(calls, INSTALLATION_URL);
      for (const found of stringsIn(answer)) {
        expect([found, found.includes(private_key)]).toEqual([found, false]);
        expect([found, found.includes(jwt)]).toEqual([found, false]);
      }
      // The token itself is the one thing a successful mint does hand back —
      // and nowhere else, so a refusal must never carry it.
      if (!answer.ok) {
        for (const found of stringsIn(answer)) {
          expect([found, found.includes(MINTED)]).toEqual([found, false]);
        }
      }
    }
  });
});

describe("a push authenticated by the App", () => {
  it("mints first, then walks the same six calls with the minted token", async () => {
    const { fetch, calls } = github(await whole());
    const adapter = await appAdapter(fetch);
    const answer = await adapter.push({
      prefix: PREFIX,
      files: FILES,
      message: MESSAGE,
    });

    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `GET ${INSTALLATION_URL}`,
      `POST ${MINT_URL}`,
      `GET ${TREES}`,
      `GET ${REF}`,
      `POST ${WRITE_TREE}`,
      `POST ${WRITE_COMMIT}`,
      `PATCH ${MOVE_REF}`,
    ]);
    expect(answer).toMatchObject({
      ok: true,
      commit: NEW_COMMIT,
      tree: NEW_TREE,
      changed: FILES.length,
      unchanged: false,
    });

    const jwt = await appJwt(await credentials(), NOW);
    for (const call of calls.slice(0, 2)) {
      expect(call.headers["authorization"]).toBe(`Bearer ${jwt}`);
    }
    for (const call of calls.slice(2)) {
      expect([call.url, call.headers["authorization"]]).toEqual([
        call.url,
        `Bearer ${MINTED}`,
      ]);
      expect([call.url, call.headers["user-agent"]]).toEqual([
        call.url,
        "nomankind-mirror",
      ]);
    }
  });

  it("mints once per push and not once per call", async () => {
    const { fetch, calls } = github(await whole());
    const adapter = await appAdapter(fetch);
    await adapter.push({ prefix: PREFIX, files: FILES, message: MESSAGE });
    await adapter.push({ prefix: PREFIX, files: FILES, message: MESSAGE });
    expect(calls.filter((call) => call.url === MINT_URL)).toHaveLength(2);
  });

  it("answers the minting failure when there is nothing to push with", async () => {
    const { fetch, calls } = github(
      await whole({ [INSTALLATION_URL]: { status: 404 } }),
    );
    const adapter = await appAdapter(fetch);
    expect(
      await adapter.push({ prefix: PREFIX, files: FILES, message: MESSAGE }),
    ).toEqual({
      ok: false,
      reason: "mirror_failed",
      detail: "app_not_installed",
    });
    // The six never started: an unauthenticated push writes nothing.
    expect(calls).toHaveLength(1);
  });

  it("still writes nothing on a day the repository already holds", async () => {
    const tree: unknown[] = [];
    for (const file of FILES) {
      tree.push({
        path: `${PREFIX}/${file.path}`,
        type: "blob",
        sha: await gitBlobSha(file.content),
      });
    }
    const { fetch, calls } = github(
      await whole({
        [TREES]: { status: 200, body: { sha: HEAD_TREE, truncated: false, tree } },
      }),
    );
    const adapter = await appAdapter(fetch);
    expect(
      await adapter.push({ prefix: PREFIX, files: FILES, message: MESSAGE }),
    ).toMatchObject({ ok: true, changed: 0, unchanged: true });
    expect(calls.map((call) => call.url)).toEqual([
      INSTALLATION_URL,
      MINT_URL,
      TREES,
      REF,
    ]);
  });

  it("never puts the key, the JWT or the token in anything the push answers", async () => {
    const { private_key } = await credentials();
    const tables = [
      await whole(),
      await whole({ [INSTALLATION_URL]: { status: 401 } }),
      await whole({ [INSTALLATION_URL]: { status: 200, text: "not json" } }),
      await whole({ [MOVE_REF]: { status: 409 } }),
      await whole({ [REF]: { status: 500 } }),
    ];
    for (const table of tables) {
      const { fetch, calls } = github(table);
      const adapter = await appAdapter(fetch);
      const answer = await adapter.push({
        prefix: PREFIX,
        files: FILES,
        message: MESSAGE,
      });
      const jwt = sentJwt(calls, INSTALLATION_URL);
      for (const found of stringsIn(answer)) {
        expect([found, found.includes(private_key)]).toEqual([found, false]);
        expect([found, found.includes(jwt)]).toEqual([found, false]);
        expect([found, found.includes(MINTED)]).toEqual([found, false]);
      }
    }
  });

  it("never calls fetch with the adapter itself as the receiver", async () => {
    // The fake throws "Illegal invocation" on a bound receiver, so an answer
    // coming back at all is the check — for the two minting calls too.
    const { fetch } = github(await whole());
    const adapter = await appAdapter(fetch);
    expect(
      await adapter.push({ prefix: PREFIX, files: FILES, message: MESSAGE }),
    ).toMatchObject({ ok: true });
  });
});

describe("which credential an environment picks", () => {
  const bothApp = {
    MIRROR_APP_ID: APP_ID,
    MIRROR_APP_PRIVATE_KEY: "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n",
  };

  it("takes the App before the token, and calls it github either way", async () => {
    // Both credentials set, and only one of them may reach GitHub: the App
    // mints, and the minted token — not MIRROR_TOKEN — carries the six.
    const { adapter, calls } = await pushFromEnv({
      MIRROR_APP_ID: APP_ID,
      MIRROR_APP_PRIVATE_KEY: (await credentials()).private_key,
      MIRROR_TOKEN: ENV_TOKEN,
    });
    expect(adapter).toBeInstanceOf(GitHubMirrorAdapter);
    expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
      `GET ${ENV_INSTALLATION_URL}`,
      `POST ${ENV_MINT_URL}`,
      `GET ${ENV_TREES}`,
      `GET ${ENV_REF}`,
      `POST ${ENV_WRITE_TREE}`,
      `POST ${ENV_WRITE_COMMIT}`,
      `PATCH ${ENV_MOVE_REF}`,
    ]);
    const jwt = sentJwt(calls, ENV_INSTALLATION_URL);
    for (const call of calls.slice(0, 2)) {
      expect([call.url, call.headers["authorization"]]).toEqual([
        call.url,
        `Bearer ${jwt}`,
      ]);
    }
    for (const call of calls.slice(2)) {
      expect([call.url, call.headers["authorization"]]).toEqual([
        call.url,
        `Bearer ${MINTED}`,
      ]);
    }
    // The environment's token was set the whole time and went nowhere.
    for (const call of calls) {
      for (const found of stringsIn(call)) {
        expect([call.url, found.includes(ENV_TOKEN)]).toEqual([call.url, false]);
      }
    }
    expect(mirrorKindFor({ ...bothApp, MIRROR_TOKEN: ENV_TOKEN })).toBe("github");
    expect(mirrorKindFor(bothApp)).toBe("github");
  });

  it("sends the token itself when the token is the credential it has", async () => {
    const { adapter, calls } = await pushFromEnv({ MIRROR_TOKEN: ENV_TOKEN });
    expect(adapter).toBeInstanceOf(GitHubMirrorAdapter);
    // No minting: a token is the credential, so the six start at the tree.
    expect(calls.map((call) => call.url)).toEqual([
      ENV_TREES,
      ENV_REF,
      ENV_WRITE_TREE,
      ENV_WRITE_COMMIT,
      ENV_MOVE_REF,
    ]);
    for (const call of calls) {
      expect([call.url, call.headers["authorization"]]).toEqual([
        call.url,
        `Bearer ${ENV_TOKEN}`,
      ]);
    }
  });

  it("mints when the App secrets are the ones set", async () => {
    const { fetch, calls } = github(await whole());
    const adapter = mirrorAdapterFor({
      MIRROR_APP_ID: APP_ID,
      MIRROR_APP_PRIVATE_KEY: (await credentials()).private_key,
    });
    expect(adapter).toBeInstanceOf(GitHubMirrorAdapter);
    // Built off the environment, so it holds policy's addresses; pointed at the
    // fake by a second adapter with the same credential.
    const pointed = new GitHubMirrorAdapter({
      app: await credentials(),
      fetch,
      repository: REPOSITORY,
      branch: BRANCH,
      api: API,
      now: () => NOW,
    });
    await pointed.push({ prefix: PREFIX, files: FILES, message: MESSAGE });
    expect(calls[0]!.url).toBe(INSTALLATION_URL);
  });

  it("falls back to the token when only half the App is set", () => {
    for (const half of [
      { MIRROR_APP_ID: APP_ID },
      { MIRROR_APP_PRIVATE_KEY: "a-key" },
      { MIRROR_APP_ID: "", MIRROR_APP_PRIVATE_KEY: "a-key" },
      { MIRROR_APP_ID: APP_ID, MIRROR_APP_PRIVATE_KEY: "" },
    ]) {
      expect(mirrorKindFor({ ...half, MIRROR_TOKEN: "a-token" })).toBe("github");
      expect(mirrorAdapterFor({ ...half })).toBeInstanceOf(
        UnavailableMirrorAdapter,
      );
    }
  });

  it("is unavailable with neither, and says so rather than pretending", async () => {
    expect(mirrorKindFor({})).toBe("unavailable");
    expect(await mirrorAdapterFor({}).push({
      prefix: PREFIX,
      files: FILES,
      message: MESSAGE,
    })).toEqual({ ok: false, reason: "mirror_unavailable", detail: null });
  });
});

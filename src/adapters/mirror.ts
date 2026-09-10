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
 * There are two ways to be allowed to write, and the six calls are the same
 * either way. A personal access token is the credential itself, and it expires:
 * somebody has to remember, on a date nobody wrote down, or the daily export
 * stops and the status page goes red for a reason that has nothing to do with
 * the log. A GitHub App does not expire — the App's private key mints a short
 * installation token at the start of each push, two calls before the six, and
 * that token dies with the push that minted it. So the App is the credential
 * this adapter prefers, and the token stays as the fallback for an instance
 * that has not made one. The private key and the minted token are held to
 * exactly the discipline the token is: one header, and nothing else, ever.
 *
 * The platform fetch goes out with no receiver, for the reason every adapter
 * here does it (workerd's "Illegal invocation", the M13 lesson).
 *
 * No policy number lives here: the addresses come from MIRROR and the timeout
 * from FETCH_TIMEOUT_MS.
 */

import { base64Decode, base64urlEncode } from "../encoding.js";
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * A GitHub App's credentials: its id, and the private key it signs with.
 *
 * `private_key` is the PEM GitHub hands over once, when the App's key is
 * created, and it is accepted in every shape a maintainer can arrive with: the
 * downloaded file with its newlines intact, the same text with the newlines
 * lost to a dashboard field that keeps one line, and the same text with the
 * newlines spelt as literal backslash-n. A credential that has to be pasted in
 * exactly one format is a credential that gets pasted wrong. PKCS#1 (`-----
 * BEGIN RSA PRIVATE KEY-----`) is what GitHub downloads; PKCS#8 (`-----BEGIN
 * PRIVATE KEY-----`) is what a maintainer who has already converted it holds,
 * and both are read.
 *
 * Both fields are Worker secrets (D-016). The key is never logged, never
 * returned and never put in a refusal's detail, exactly as the token is not.
 */
export interface GitHubAppCredentials {
  /** The App id, as the App's own settings page shows it. */
  readonly app_id: string;
  /** The App's private key, PEM. Never logged and never in a refusal. */
  readonly private_key: string;
}

/**
 * The algorithm a GitHub App JWT is signed with. A wire fact, not policy:
 * GitHub names RS256 and reads nothing else.
 */
const RS256: RsaHashedImportParams = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
};

/**
 * How far back the JWT's `iat` sits and how far ahead its `exp`.
 *
 * Wire facts and not policy, exactly as the API version above is: GitHub
 * refuses a JWT whose `exp` is more than ten minutes out and one whose `iat` is
 * in the server's own past-that-is-its-future, so a minute of backdating covers
 * a clock that drifts and nine minutes stays inside the ten GitHub allows.
 */
const JWT_BACKDATE_SECONDS = 60;
const JWT_LIFETIME_SECONDS = 9 * 60;

const SECOND_MS = 1000;

/** The armour lines of a PEM, whatever they name. */
const PEM_ARMOUR = /-----(?:BEGIN|END)[A-Za-z ]*-----/g;

/** Every space, tab and newline between them. */
const PEM_SPACE = /\s/g;

/** What a PKCS#1 PEM calls itself, and so how the two forms are told apart. */
const PKCS1_LABEL = "BEGIN RSA PRIVATE KEY";

const encoder = new TextEncoder();

/** DER's SEQUENCE and OCTET STRING tags, and where its short length form ends. */
const DER_SEQUENCE = 0x30;
const DER_OCTET_STRING = 0x04;
const DER_SHORT_FORM = 0x80;
const DER_BYTE = 256;

/**
 * The RSA algorithm identifier, DER: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }.
 * A constant of the encoding, spelt out because it never varies.
 */
const RSA_ALGORITHM = Uint8Array.of(
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  0x05, 0x00,
);

/** PKCS#8's version field, DER: INTEGER 0. */
const PKCS8_VERSION = Uint8Array.of(0x02, 0x01, 0x00);

function concat(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.byteLength;
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.byteLength;
  }
  return bytes;
}

/**
 * A DER length: the short form under 128, and above it a count of bytes
 * followed by that many big-endian bytes. Written for any length rather than
 * for the one a 2048-bit key happens to have, because a 4096-bit key is a key
 * somebody will paste in one day.
 */
function derLength(length: number): Uint8Array {
  if (length < DER_SHORT_FORM) return Uint8Array.of(length);
  const bytes: number[] = [];
  for (let rest = length; rest > 0; rest = Math.floor(rest / DER_BYTE)) {
    bytes.unshift(rest % DER_BYTE);
  }
  return Uint8Array.from([DER_SHORT_FORM | bytes.length, ...bytes]);
}

/** One DER element: its tag, its length, its content. */
function derElement(tag: number, content: Uint8Array): Uint8Array {
  return concat([Uint8Array.of(tag), derLength(content.length), content]);
}

/**
 * A PKCS#1 RSAPrivateKey wrapped as a PKCS#8 PrivateKeyInfo.
 *
 * Pure, and here for one reason: WebCrypto imports `pkcs8` and nothing else,
 * and what GitHub downloads is PKCS#1. The wrapper is three fields around bytes
 * this function never looks inside — SEQUENCE { INTEGER 0, SEQUENCE { OID
 * 1.2.840.113549.1.1.1, NULL }, OCTET STRING { the PKCS#1 DER } } — so a key
 * that was not a valid RSAPrivateKey to begin with is refused by
 * `crypto.subtle.importKey` rather than quietly accepted here.
 */
export function pkcs1ToPkcs8(der: Uint8Array): Uint8Array {
  return derElement(
    DER_SEQUENCE,
    concat([PKCS8_VERSION, RSA_ALGORITHM, derElement(DER_OCTET_STRING, der)]),
  );
}

/**
 * The PKCS#8 DER inside a private key PEM, in whichever of the three paste
 * shapes and whichever of the two structures it arrived in.
 */
function privateKeyDer(pem: string): Uint8Array {
  const text = pem.replaceAll("\\n", "\n");
  const der = base64Decode(text.replace(PEM_ARMOUR, "").replace(PEM_SPACE, ""));
  return text.includes(PKCS1_LABEL) ? pkcs1ToPkcs8(der) : der;
}

/** One JWT segment: the JSON, UTF-8, unpadded base64url. */
function jwtSegment(value: unknown): string {
  return base64urlEncode(encoder.encode(JSON.stringify(value)));
}

/**
 * The JWT a GitHub App authenticates as itself with.
 *
 * The clock is the caller's, like every other clock in the kernel: the sweep
 * runs on an injected one and a test runs on a fake, so nothing here reads
 * `Date.now()` on its own.
 *
 * The key is imported unextractable, so the CryptoKey this makes cannot hand
 * the secret back out again even to code in the same isolate.
 */
export async function appJwt(
  credentials: GitHubAppCredentials,
  now: Date,
): Promise<string> {
  const key = await globalThis.crypto.subtle.importKey(
    "pkcs8",
    privateKeyDer(credentials.private_key) as unknown as BufferSource,
    RS256,
    false,
    ["sign"],
  );
  const seconds = Math.floor(now.getTime() / SECOND_MS);
  const signed = `${jwtSegment({ alg: "RS256", typ: "JWT" })}.${jwtSegment({
    iat: seconds - JWT_BACKDATE_SECONDS,
    exp: seconds + JWT_LIFETIME_SECONDS,
    iss: credentials.app_id,
  })}`;
  const signature = await globalThis.crypto.subtle.sign(
    RS256.name,
    key,
    encoder.encode(signed) as unknown as BufferSource,
  );
  return `${signed}.${base64urlEncode(new Uint8Array(signature))}`;
}

/** What minting an installation token needs. */
export interface InstallationTokenOptions {
  readonly fetch: typeof fetch;
  /** `owner/name`, the repository the token is scoped to. */
  readonly repository: string;
  readonly api: string;
  /** The instant the JWT is dated from. Injected, never read from the clock. */
  readonly now: Date;
}

/** A minted token, or the named refusal that stands in its place. */
export type InstallationToken =
  | { readonly ok: true; readonly token: string; readonly expires_at: string }
  | {
      readonly ok: false;
      readonly reason: "mirror_failed";
      /** One word or a status. Never the key and never the token. */
      readonly detail: string;
    };

function mintFailed(detail: string): InstallationToken {
  return { ok: false, reason: "mirror_failed", detail };
}

/** One minting call's answer: the parsed body, or a status and its word. */
type MintAnswer =
  | { readonly ok: true; readonly body: unknown }
  | { readonly ok: false; readonly status: number; readonly detail: string };

/**
 * One of the two minting calls.
 *
 * Separate from the adapter's own `#call` because these two are made with the
 * App's JWT rather than with the push's bearer, and they refuse in words of
 * their own: a 404 here is an App that is not installed, not a repository that
 * does not exist. Nothing of a throw travels, for the reason it does not in the
 * push: a fetch's error can carry the request's headers, and one of them is the
 * JWT.
 */
async function mintCall(
  call: typeof fetch,
  url: string,
  init: RequestInit,
): Promise<MintAnswer> {
  let response: Response;
  try {
    response = await call(url, {
      ...init,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch {
    return { ok: false, status: 0, detail: "network" };
  }
  if (!response.ok) {
    return {
      ok: false,
      status: response.status,
      detail:
        response.status === UNAUTHORIZED ? "app_auth" : String(response.status),
    };
  }
  try {
    return { ok: true, body: await response.json() };
  } catch {
    return { ok: false, status: 0, detail: "bad_response" };
  }
}

/** The bare repository name a scoped token names, off `owner/name`. */
function repositoryName(repository: string): string {
  return repository.slice(repository.indexOf("/") + 1);
}

/**
 * Mint an installation token for the mirror repository.
 *
 * Two calls: which installation of this App the repository has, and then a
 * token for that installation scoped to that one repository with `contents:
 * write` and nothing else — the narrowest thing that can still push, so a
 * leaked token is a token that can write one repository's files for an hour.
 *
 * Never throws, and never says anything a credential could be read out of. A
 * 404 on the first call is the one failure a maintainer will actually hit: the
 * App exists and the key is good, and nobody installed it on the repository.
 */
export async function installationToken(
  credentials: GitHubAppCredentials,
  options: InstallationTokenOptions,
): Promise<InstallationToken> {
  let jwt: string;
  try {
    jwt = await appJwt(credentials, options.now);
  } catch {
    // The PEM did not decode or the key did not import. Named in one word, and
    // nothing of the throw travels: its message can carry the key's own bytes.
    return mintFailed("app_key");
  }

  const call = options.fetch;
  const headers: Record<string, string> = {
    authorization: `Bearer ${jwt}`,
    accept: GITHUB_ACCEPT,
    "x-github-api-version": GITHUB_API_VERSION,
    "user-agent": USER_AGENT,
  };

  const installation = await mintCall(
    call,
    `${options.api}/repos/${options.repository}/installation`,
    { method: "GET", headers },
  );
  if (!installation.ok) {
    return mintFailed(
      installation.status === NOT_FOUND
        ? "app_not_installed"
        : installation.detail,
    );
  }
  const id = isRecord(installation.body) ? installation.body["id"] : null;
  if (typeof id !== "number" && typeof id !== "string") {
    return mintFailed("bad_response");
  }

  const minted = await mintCall(
    call,
    `${options.api}/app/installations/${id}/access_tokens`,
    {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({
        repositories: [repositoryName(options.repository)],
        permissions: { contents: "write" },
      }),
    },
  );
  if (!minted.ok) return mintFailed(minted.detail);

  const token = isRecord(minted.body) ? minted.body["token"] : null;
  const expires = isRecord(minted.body) ? minted.body["expires_at"] : null;
  if (typeof token !== "string" || typeof expires !== "string") {
    return mintFailed("bad_response");
  }
  return { ok: true, token, expires_at: expires };
}

/**
 * One credential or the other, and never both and never neither.
 *
 * A union rather than two optional fields, because it is the union that lets
 * the push below have no "no credential" branch at all: there is no third case
 * to write a refusal for.
 */
type MirrorCredential =
  | {
      /** The write credential itself. Never logged and never in a refusal. */
      readonly token: string;
      readonly app?: undefined;
    }
  | {
      /** The App that mints one per push. Never logged and never in a refusal. */
      readonly app: GitHubAppCredentials;
      readonly token?: undefined;
    };

/**
 * What the adapter needs to be built: one credential, and where to send it.
 *
 * The credential is one or the other and never both, which the type says rather
 * than a comment: an adapter holding a token and an App would have to pick, and
 * the place to pick is `mirrorAdapterFor` below, once, off the environment.
 */
export type GitHubMirrorOptions = {
  readonly fetch?: typeof fetch;
  readonly repository?: string;
  readonly branch?: string;
  readonly api?: string;
  /**
   * The clock the App JWT is dated from. Injected everywhere time matters, so
   * a test can say what minute it is; unused by a token adapter, which asks
   * nothing about the time.
   */
  readonly now?: () => Date;
} & MirrorCredential;

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

  readonly #credential: MirrorCredential;
  readonly #fetch: typeof fetch;
  readonly #repository: string;
  readonly #branch: string;
  readonly #api: string;
  readonly #now: () => Date;

  constructor(options: GitHubMirrorOptions) {
    this.#credential =
      options.token === undefined
        ? { app: options.app }
        : { token: options.token };
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#repository = options.repository ?? MIRROR.repository;
    this.#branch = options.branch ?? MIRROR.branch;
    this.#api = options.api ?? MIRROR.api;
    this.#now = options.now ?? (() => new Date());
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
   * The credential this push writes with.
   *
   * A token is itself the answer. An App mints one here, two calls before the
   * six, and the minting is memoized by being done exactly once per push and
   * never held afterwards: a token that outlived the push that needed it would
   * be a credential this object was storing for no reason. A minting failure is
   * the push's answer, in the words `installationToken` chose.
   */
  async #bearer(): Promise<string | MirrorPush> {
    // No third case: `MirrorCredential` is a token or an App and never neither.
    if (this.#credential.token !== undefined) return this.#credential.token;
    const minted = await installationToken(this.#credential.app, {
      fetch: this.#fetch,
      repository: this.#repository,
      api: this.#api,
      now: this.#now(),
    });
    return minted.ok ? minted.token : failed(minted.detail);
  }

  /**
   * Every call goes through here: the headers, the timeout, no receiver.
   *
   * `moving` says this call is the one that moves the branch ref, which is the
   * only place a 409 or a 422 means "somebody else pushed first" rather than
   * "that request was wrong".
   */
  async #call(
    bearer: string,
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
          authorization: `Bearer ${bearer}`,
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
    // (0) The bearer the six calls carry, which for an App is two calls of its
    // own. A push that cannot be authenticated answers that and stops here.
    const bearer = await this.#bearer();
    if (typeof bearer !== "string") return bearer;

    // (1) The branch's whole tree. The branch name is accepted where a tree sha
    // goes, so this is one call rather than two.
    const tree = await this.#call(
      bearer,
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
      bearer,
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
    const written = await this.#call(
      bearer,
      `/repos/${this.#repository}/git/trees`,
      {
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
      },
    );
    if (!written.ok) return written.refusal;
    const treeSha = isRecord(written.body) ? written.body["sha"] : null;
    if (typeof treeSha !== "string") return failed("bad_response");

    // (5) The commit.
    const commit = await this.#call(
      bearer,
      `/repos/${this.#repository}/git/commits`,
      {
        method: "POST",
        body: JSON.stringify({
          message: input.message,
          tree: treeSha,
          parents: [head],
        }),
      },
    );
    if (!commit.ok) return commit.refusal;
    const commitSha = isRecord(commit.body) ? commit.body["sha"] : null;
    if (typeof commitSha !== "string") return failed("bad_response");

    // (6) The ref, without force: the other environment may have pushed while
    // this export was being built, and losing that race is a conflict the next
    // run repairs rather than a commit that overwrites somebody else's.
    const moved = await this.#call(
      bearer,
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

/** The secrets an environment can carry a mirror credential in. */
export interface MirrorEnv {
  /** A personal access token with push access: the fallback credential. */
  readonly MIRROR_TOKEN?: string;
  /** The GitHub App's id, half of the credential that never expires. */
  readonly MIRROR_APP_ID?: string;
  /** The GitHub App's private key, PEM. The other half. */
  readonly MIRROR_APP_PRIVATE_KEY?: string;
}

/** A secret that is actually set: a string, and not the empty one. */
function secret(value: string | undefined): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

/**
 * Which track this environment runs (decision D-013 as amended).
 *
 * The credential and not the environment name decides it: both demo and
 * production push to the same repository under their own directories, and a
 * maintainer who has not set a secret gets an environment that says so rather
 * than one that fails a call every day.
 *
 * The App comes first, and the kind is "github" either way: which credential
 * authenticated a push is not something the status page has an opinion about,
 * and the export lands in the same place under either. A maintainer moving off
 * the token sets the two App secrets, watches one export land, and only then
 * deletes the token — the order that never leaves the mirror with no credential
 * at all.
 */
export function mirrorAdapterFor(env: MirrorEnv): MirrorAdapter {
  const appId = secret(env.MIRROR_APP_ID);
  const privateKey = secret(env.MIRROR_APP_PRIVATE_KEY);
  if (appId !== null && privateKey !== null) {
    return new GitHubMirrorAdapter({
      app: { app_id: appId, private_key: privateKey },
    });
  }
  const token = secret(env.MIRROR_TOKEN);
  if (token === null) return new UnavailableMirrorAdapter();
  return new GitHubMirrorAdapter({ token });
}

/** The same branch, as a word: what the status page and the mirror page show. */
export function mirrorKindFor(env: MirrorEnv): MirrorKind {
  return mirrorAdapterFor(env).kind;
}

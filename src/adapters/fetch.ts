/**
 * The capture fetch, step 1 of the norm rule.
 *
 * Snapshot normalization rule, step 1 (Fetch): "One HTTP GET, no JavaScript
 * execution, no cookies, no authentication. Fixed request headers ... Follow up
 * to five redirects; the final URL is recorded in the sidecar. Timeout thirty
 * seconds."
 *
 * The headers are fixed by the rule and are written out below, because a
 * capture taken with different headers is a capture of a different page: the
 * `Accept` line is what asks a content-negotiating server for the document the
 * hash is over, and `Accept-Encoding: identity` is what makes the archived
 * bytes the bytes the server sent. Redirects are followed by hand, with
 * `redirect: "manual"`, so the chain is counted and the final URL is known;
 * `fetch`'s own following would hide both.
 *
 * `fetch` never throws. Every way a capture can fail is one of five named
 * reasons the route reports to the submitter unchanged. The two numbers here —
 * how many redirects and how long — are src/policy.ts's, and the byte ceiling
 * is too; none is written down in this file.
 *
 * The network is reached through an injected fetch function, so a test drives
 * the real fetcher without reaching the internet.
 */

import {
  CAPTURE_MAX_BYTES,
  FETCH_MAX_REDIRECTS,
  FETCH_TIMEOUT_MS,
} from "../policy.js";

/**
 * The four fixed request headers of norm-v1.2, exactly as the rule writes them.
 * Not policy numbers: they are the wire format of a capture, and they move only
 * when the rule version moves.
 */
export const SNAPSHOT_REQUEST_HEADERS: Readonly<Record<string, string>> =
  Object.freeze({
    "user-agent": "nomankind-snapshot/1 (+https://nomankind.ai/norm)",
    accept:
      "text/html,application/json,application/pdf,text/plain;q=0.9,*/*;q=0.5",
    "accept-language": "en",
    "accept-encoding": "identity",
  });

/** Every reason a capture can be refused. */
export type FetchRefusal =
  | "fetch_failed"
  | "too_many_redirects"
  | "timeout"
  | "too_large"
  | "bad_status";

/** Every refusal, so a caller can enumerate them. */
export const FETCH_REFUSALS: readonly FetchRefusal[] = Object.freeze([
  "fetch_failed",
  "too_many_redirects",
  "timeout",
  "too_large",
  "bad_status",
] as const);

/** A capture, or the refusal that stopped it. */
export type FetchResult =
  | {
      ok: true;
      bytes: Uint8Array;
      status: number;
      /** Response headers, lowercased, without set-cookie. */
      headers: Record<string, string>;
      /** The URL the body actually came from, after every redirect. */
      finalUrl: string;
    }
  | { ok: false; reason: FetchRefusal };

/** Somewhere to fetch a citation from. */
export interface SnapshotFetcher {
  fetch(url: string): Promise<FetchResult>;
}

/** The redirect statuses step 1 follows. */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([
  301, 302, 303, 307, 308,
]);

/** The status range a capture is taken from: 2xx and nothing else. */
const OK_MIN = 200;
const OK_MAX = 299;

/**
 * The header a response says its own length in, and the one header never
 * recorded: a sidecar is public evidence, and a cookie is not evidence.
 */
const CONTENT_LENGTH = "content-length";
const SET_COOKIE = "set-cookie";

/** Every response header but the cookie, lowercased. */
function headersOf(response: Response): Record<string, string> {
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    const name = key.toLowerCase();
    if (name === SET_COOKIE) return;
    headers[name] = value;
  });
  return headers;
}

/** The declared length, or null when the header is absent or not a count. */
function declaredLength(response: Response): number | null {
  const raw = response.headers.get(CONTENT_LENGTH);
  if (raw === null) return null;
  const length = Number(raw);
  return Number.isInteger(length) && length >= 0 ? length : null;
}

/** Whether a redirect target is one this rule may follow. */
function isHttpUrl(url: URL): boolean {
  return url.protocol === "http:" || url.protocol === "https:";
}

/**
 * Read a body, refusing one that runs past the ceiling.
 *
 * A server that declared its length has already been checked; this is for the
 * one that did not, and it stops at the first chunk that crosses the line
 * rather than buffering a whole download to find out it was too big.
 */
async function readBody(response: Response): Promise<Uint8Array | null> {
  const body = response.body;
  if (body === null || body === undefined) {
    const buffer = await response.arrayBuffer();
    return buffer.byteLength > CAPTURE_MAX_BYTES ? null : new Uint8Array(buffer);
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    total += value.byteLength;
    if (total > CAPTURE_MAX_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

/**
 * The fetcher the Worker runs: the norm rule's step 1 over an injected fetch.
 *
 * The timeout covers the whole operation — every hop of the redirect chain and
 * the body read together — because thirty seconds is what the rule gives a
 * capture, not what it gives each request inside one.
 */
export class WebFetcher implements SnapshotFetcher {
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  /**
   * `timeoutMs` is injectable so a test can watch a hung fetch time out without
   * waiting for the real window; the default is the policy number and nothing
   * else, and the deployed Worker passes neither argument.
   *
   * The default is bound to `globalThis` because a platform `fetch` is a method
   * of the global object and workerd throws "Illegal invocation" when it is
   * called on anything else. Node's does not, so nothing but a real deployment
   * would have shown it.
   */
  constructor(
    fetchFn: typeof fetch = globalThis.fetch.bind(globalThis),
    timeoutMs: number = FETCH_TIMEOUT_MS,
  ) {
    this.#fetch = fetchFn;
    this.#timeoutMs = timeoutMs;
  }

  async fetch(url: string): Promise<FetchResult> {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.#timeoutMs);

    try {
      return await this.#capture(url, controller.signal);
    } catch {
      return { ok: false, reason: timedOut ? "timeout" : "fetch_failed" };
    } finally {
      clearTimeout(timer);
    }
  }

  /** The chain, the status check and the body. Throws only on a real failure. */
  async #capture(url: string, signal: AbortSignal): Promise<FetchResult> {
    let current: URL;
    try {
      current = new URL(url);
    } catch {
      return { ok: false, reason: "fetch_failed" };
    }
    if (!isHttpUrl(current)) return { ok: false, reason: "fetch_failed" };

    // Read out of the field first, so the call has no receiver: `this.#fetch()`
    // would pass this WebFetcher as `this`, and a platform fetch refuses to be
    // called on anything but the global object.
    const call = this.#fetch;

    let redirects = 0;
    for (;;) {
      const response = await call(current.toString(), {
        method: "GET",
        headers: { ...SNAPSHOT_REQUEST_HEADERS },
        redirect: "manual",
        signal,
      });

      const location = response.headers.get("location");
      if (REDIRECT_STATUSES.has(response.status) && location !== null) {
        redirects += 1;
        if (redirects > FETCH_MAX_REDIRECTS) {
          return { ok: false, reason: "too_many_redirects" };
        }
        let next: URL;
        try {
          next = new URL(location, current);
        } catch {
          return { ok: false, reason: "fetch_failed" };
        }
        if (!isHttpUrl(next)) return { ok: false, reason: "fetch_failed" };
        current = next;
        continue;
      }

      if (response.status < OK_MIN || response.status > OK_MAX) {
        return { ok: false, reason: "bad_status" };
      }

      const declared = declaredLength(response);
      if (declared !== null && declared > CAPTURE_MAX_BYTES) {
        return { ok: false, reason: "too_large" };
      }

      const bytes = await readBody(response);
      if (bytes === null) return { ok: false, reason: "too_large" };

      return {
        ok: true,
        bytes,
        status: response.status,
        headers: headersOf(response),
        finalUrl: current.toString(),
      };
    }
  }
}

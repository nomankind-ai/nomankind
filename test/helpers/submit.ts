/**
 * What the submit tests need to act like a real submitter: real keys, real
 * signatures over the real canonical core, and a fetcher that answers from a
 * table instead of the internet.
 *
 * Every key here is generated through WebCrypto and every signature is made by
 * it, so a test that passes says the Worker verified a real Ed25519 signature
 * over the real JCS bytes. Only the network is faked, because only the network
 * is not ours to run in a test — and the fixture pages are real bytes, hashed
 * by the real norm rule, so a snapshot_hash a test computes is one the Worker
 * has to arrive at independently.
 */

import type { FetchResult, SnapshotFetcher } from "../../src/adapters/fetch.js";
import type { Core } from "../../src/core.js";
import { snapshotHash } from "../../src/normalize.js";
import { FETCH_MAX_REDIRECTS } from "../../src/policy.js";
import { signCore } from "../../src/sign.js";
import { DEFAULT_DOMAIN } from "../../src/policy.js";
import { buildSubmittedCore, type SubmissionProposal } from "../../src/submit.js";
import { signedPost, type TestAgent } from "./registry.js";

/** The instant every request in the submit tests is served at. */
export const SUBMIT_NOW = new Date("2026-09-08T12:00:00.000Z");

/** The same instant as the injected derivation clock. */
export const SUBMIT_CLOCK = { now: SUBMIT_NOW.toISOString() };

/** One page the fixture fetcher serves. */
export interface FixturePage {
  /** The body as it comes off the wire. */
  readonly body: string | Uint8Array;
  readonly contentType?: string;
  readonly status?: number;
  /** When set, this URL redirects there instead of answering. */
  readonly location?: string;
}

const encoder = new TextEncoder();

/** A fixture page's bytes, exactly as the fetcher would return them. */
export function bytesOf(page: FixturePage): Uint8Array {
  return typeof page.body === "string" ? encoder.encode(page.body) : page.body;
}

/**
 * The snapshot hash of a fixture page under the real norm rule. A test that
 * wants a matching hash asks for it here; one that wants a mismatch supplies
 * its own value.
 */
export async function pageHash(page: FixturePage): Promise<string> {
  const hashed = await snapshotHash(bytesOf(page), page.contentType ?? null);
  if (!hashed.ok) {
    throw new Error(`pageHash: the fixture page is refused: ${hashed.reason}`);
  }
  return hashed.hash;
}

/**
 * A SnapshotFetcher reading from a map instead of the network.
 *
 * A URL that is not in the map cannot be fetched at all; a page carrying a
 * `location` redirects, and the chain is followed and counted here exactly as
 * the real fetcher counts it, so a test can watch a final URL land in the
 * sidecar. `requests` records every URL asked for, which is how a test asserts
 * that a refusal happened before the network was reached.
 */
export class FixtureFetcher implements SnapshotFetcher {
  readonly #pages: Map<string, FixturePage>;
  readonly requests: string[] = [];

  constructor(pages: Record<string, FixturePage>) {
    this.#pages = new Map(Object.entries(pages));
  }

  async fetch(url: string): Promise<FetchResult> {
    this.requests.push(url);
    let current = url;
    let redirects = 0;
    for (;;) {
      const page = this.#pages.get(current);
      if (page === undefined) return { ok: false, reason: "fetch_failed" };

      if (page.location !== undefined) {
        redirects += 1;
        if (redirects > FETCH_MAX_REDIRECTS) {
          return { ok: false, reason: "too_many_redirects" };
        }
        current = new URL(page.location, current).toString();
        continue;
      }

      const status = page.status ?? 200;
      if (status < 200 || status > 299) return { ok: false, reason: "bad_status" };

      const headers: Record<string, string> = {};
      if (page.contentType !== undefined) {
        headers["content-type"] = page.contentType;
      }
      return {
        ok: true,
        bytes: bytesOf(page),
        status,
        headers,
        finalUrl: current,
      };
    }
  }
}

/**
 * The core an agent is about to sign, built by the real submit kernel.
 *
 * `domain` defaults to ai-ecosystem so a test that is not about domains does not
 * have to name one; a test that is about them passes its own (decision D-071).
 */
export function submittedCore(
  agent: TestAgent,
  proposal: Omit<SubmissionProposal, "author" | "domain"> & {
    readonly domain?: string;
  },
): Promise<Core> {
  return buildSubmittedCore(
    {
      domain: DEFAULT_DOMAIN,
      ...proposal,
      author: agent.agentId,
    },
    SUBMIT_CLOCK,
  );
}

/**
 * A signed POST /entries, ready to hand to the router.
 *
 * `signer` is the key that signs the request envelope and defaults to the
 * author's own; a test that wants the two to differ passes a second agent,
 * which is what the author_mismatch refusal is about.
 */
export async function submission(
  author: TestAgent,
  input: {
    readonly core: Core;
    readonly receipt?: unknown;
    readonly signer?: TestAgent;
    readonly timestamp?: string;
    readonly nonce?: string;
  },
): Promise<Request> {
  const signature = await signCore(input.core, author.privateKey);
  const body: Record<string, unknown> = {
    entry: { ...input.core, signature },
  };
  if (input.receipt !== undefined) body["receipt"] = input.receipt;

  return signedPost(input.signer ?? author, {
    path: "/entries",
    body,
    timestamp: input.timestamp ?? SUBMIT_CLOCK.now,
    nonce: input.nonce,
  });
}

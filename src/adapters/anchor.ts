/**
 * The anchor adapter: the day's hash out to an external timestamping chain.
 *
 * Whitepaper, "Lifecycle of an entry" (Seal): anchoring each day's batch hash
 * into an external chain makes the existence proof independent of the identity
 * layer. If every witness vanished tomorrow, an anchored day still proves those
 * roots existed by then — which is only true if the anchor is posted somewhere
 * nomankind does not run, so this is the one adapter whose whole value is that
 * the other end is a stranger.
 *
 * OpenTimestamps' calendar wire is small and this speaks it directly: POST the
 * 32 digest bytes to `<calendar>/digest` and keep the pending proof that comes
 * back. Which calendars, and in what order, is src/policy.ts's
 * ANCHOR_CALENDARS; no endpoint is written down here.
 *
 * Never throws and never retries in place: an anchor that could not be posted
 * today is posted on a later run, and the day's roots have not moved. The
 * platform fetch goes out with no receiver, for the reason every adapter here
 * does it (workerd's "Illegal invocation", the M13 lesson).
 */

import type { Anchor, AnchorAdapter, AnchorExternal } from "../anchor.js";
import { base64Encode } from "../encoding.js";
import { ANCHOR_CALENDARS, FETCH_TIMEOUT_MS } from "../policy.js";
import { PRODUCTION } from "./payout.js";

/** The OpenTimestamps calendar wire, as the calendars publish it. Format, not policy. */
const OTS_MEDIA_TYPE = "application/vnd.opentimestamps.v1";
const OTS_CONTENT_TYPE = "application/x-www-form-urlencoded";
const OTS_DIGEST_PATH = "/digest";

/** The User-Agent every call from this adapter carries. A wire fact, not policy. */
const USER_AGENT = "nomankind";

/** SHA-256 is 32 bytes; the calendar takes the digest and nothing around it. */
const DIGEST_BYTES = 32;

const HASH_PREFIX = "sha256:";
const HEX_64 = /^[0-9a-f]{64}$/;

/** The 32 digest bytes an anchor hash carries, or null when it carries none. */
function digestOf(hash: string): Uint8Array | null {
  if (typeof hash !== "string" || !hash.startsWith(HASH_PREFIX)) return null;
  const hex = hash.slice(HASH_PREFIX.length);
  if (!HEX_64.test(hex)) return null;
  const bytes = new Uint8Array(DIGEST_BYTES);
  for (let index = 0; index < DIGEST_BYTES; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Local and demo: the day's hash is recorded and posted nowhere.
 *
 * Null rather than an invented receipt, for the reason the payout stub refuses
 * rather than passes: a fabricated timestamp is worse than none, because it
 * looks like evidence. The anchor still exists and still commits to the day's
 * roots; it simply has no external witness, which is the truth about a laptop.
 */
export class LocalAnchorAdapter implements AnchorAdapter {
  async anchor(): Promise<AnchorExternal> {
    return null;
  }
}

/** What the OpenTimestamps adapter needs to be built. */
export interface OpenTimestampsOptions {
  fetch?: typeof fetch;
  calendars?: readonly string[];
  now: () => Date;
}

/**
 * Production's adapter: the policy's calendars, in order, until one answers.
 *
 * A calendar that is down, slow, or answers something empty is skipped and the
 * next is tried; the first usable answer is the one recorded, and its origin is
 * recorded with it so a verifier knows which calendar to upgrade the pending
 * proof against later. All of them failing is null, not an exception.
 *
 * The clock is injected like every clock in this system, so a test can pin the
 * submission time rather than read the machine's.
 */
export class OpenTimestampsAdapter implements AnchorAdapter {
  readonly #fetch: typeof fetch;
  readonly #calendars: readonly string[];
  readonly #now: () => Date;

  constructor(options: OpenTimestampsOptions) {
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#calendars = options.calendars ?? ANCHOR_CALENDARS;
    this.#now = options.now;
  }

  async anchor(anchor: Anchor): Promise<AnchorExternal> {
    try {
      return await this.#anchor(anchor);
    } catch {
      return null;
    }
  }

  async #anchor(anchor: Anchor): Promise<AnchorExternal> {
    const digest = digestOf(anchor.hash);
    if (digest === null) return null;

    for (const calendar of this.#calendars) {
      const proof = await this.#submit(calendar, digest);
      if (proof === null) continue;
      return {
        kind: "opentimestamps",
        calendar,
        submitted_at: this.#now().toISOString(),
        proof,
      };
    }
    return null;
  }

  /** One calendar's pending proof, standard base64, or null on any failure. */
  async #submit(
    calendar: string,
    digest: Uint8Array,
  ): Promise<string | null> {
    const call = this.#fetch;
    let response: Response;
    try {
      response = await call(`${calendar}${OTS_DIGEST_PATH}`, {
        method: "POST",
        headers: {
          accept: OTS_MEDIA_TYPE,
          "content-type": OTS_CONTENT_TYPE,
          "user-agent": USER_AGENT,
        },
        // The raw digest bytes, with nothing wrapped around them: the calendar
        // reads the body as the commitment itself, whatever the content type
        // its wire asks for says.
        body: digest as unknown as BodyInit,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
    } catch {
      return null;
    }

    if (!response.ok) return null;

    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(await response.arrayBuffer());
    } catch {
      return null;
    }
    if (bytes.byteLength === 0) return null;

    // Standard base64, not base64url: an .ots proof is a binary blob carried in
    // JSON, not an identifier that ever goes in a URL.
    return base64Encode(bytes);
  }
}

/** The adapter this environment runs (decision D-013 as amended). */
export function anchorAdapterFor(
  environment: string,
  now: () => Date,
): AnchorAdapter {
  return environment === PRODUCTION
    ? new OpenTimestampsAdapter({ now })
    : new LocalAnchorAdapter();
}

/**
 * Domain control, asked of the DNS.
 *
 * Whitepaper Section 11, the first joining step: "Publish a DNS TXT record on a
 * domain you control carrying your 1F916 agent id." src/registry.ts says where
 * that record lives (`_nomankind.<domain>`) and what counts as a match; this
 * module is the one place that goes and looks.
 *
 * Decision D-013 as amended: the DNS check is real on every environment, so
 * there is no fake resolver behind a flag anywhere in src/. The lookup runs
 * over DNS-over-HTTPS because a Worker has no resolver socket, and it goes
 * through `fetch`, which is the only network call the kernel makes.
 *
 * The lookup is bounded by src/policy.ts's FETCH_TIMEOUT_MS, as every other
 * outbound call in the system is: a resolver that accepts the connection and
 * then never answers would otherwise hold the registration door open for as long
 * as it liked, and the door is what an operator is waiting on.
 *
 * `txt` never throws. A resolver that is down and a domain that has no record
 * are different answers — one is the operator's fault and the other is ours —
 * and the caller turns the first into a 503 and the second into a 422. Folding
 * them together would blame an operator for our outage.
 */

import { FETCH_TIMEOUT_MS } from "../policy.js";

/** What a TXT lookup found, or why it could not say. */
export type TxtLookup =
  | { ok: true; values: string[] }
  | { ok: false; reason: "nxdomain" | "unavailable" };

/** Somewhere to ask for a name's TXT records. */
export interface DnsResolver {
  txt(name: string): Promise<TxtLookup>;
}

/** The DNS-over-HTTPS endpoint this Worker asks by default. */
export const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

/**
 * RFC 1035 section 3.2.2: TXT is record type 16. A DNS protocol constant, not
 * policy: it is what the wire format says and it does not move by decision, so
 * it does not live in src/policy.ts.
 */
export const DNS_TYPE_TXT = 16;

/**
 * RFC 1035 section 4.1.1: NXDOMAIN is rcode 3, and NOERROR is rcode 0. DNS
 * protocol constants, not policy, for the same reason as the record type.
 */
export const DNS_RCODE_NXDOMAIN = 3;
export const DNS_RCODE_NOERROR = 0;

const NXDOMAIN: TxtLookup = { ok: false, reason: "nxdomain" };
const UNAVAILABLE: TxtLookup = { ok: false, reason: "unavailable" };

/** Quoted character-strings, as a dns-json answer writes them. */
const QUOTED_CHUNK = /"([^"]*)"/g;

/**
 * One TXT record's value.
 *
 * A TXT record is a sequence of character-strings, each at most 255 octets, and
 * a long value arrives split across several of them: `"abc" "def"` is the one
 * value `abcdef`. Joining the chunks is what the DNS itself means by that
 * record, not a convenience — an agent id that straddles the split would
 * otherwise never match.
 */
function unquote(data: string): string {
  const chunks = [...data.matchAll(QUOTED_CHUNK)].map((match) => match[1]);
  return chunks.length === 0 ? data.trim() : chunks.join("");
}

/** A resolver that asks a DNS-over-HTTPS endpoint for JSON. */
export class DohResolver implements DnsResolver {
  readonly #fetch: typeof fetch;
  readonly #endpoint: string;
  /**
   * How long the lookup may take before it is given up on. The policy number
   * everywhere but in a test, which passes a small window of its own rather than
   * waiting thirty seconds to watch one expire.
   */
  readonly #timeoutMs: number;

  /**
   * The default is the platform's own fetch, and the call below reads it out of
   * the field first so it goes out with no receiver: workerd throws "Illegal
   * invocation" when a platform fetch is called on anything but the global
   * object, and Node's does not, which is why a green suite said nothing until
   * a real registration answered dns_unavailable under wrangler (the M13
   * lesson, in a third place).
   */
  constructor(
    fetchFn: typeof fetch = globalThis.fetch,
    endpoint = DOH_ENDPOINT,
    timeoutMs = FETCH_TIMEOUT_MS,
  ) {
    this.#fetch = fetchFn;
    this.#endpoint = endpoint;
    this.#timeoutMs = timeoutMs;
  }

  async txt(name: string): Promise<TxtLookup> {
    const call = this.#fetch;
    const url = `${this.#endpoint}?name=${encodeURIComponent(name)}&type=TXT`;
    let payload: unknown;
    try {
      const response = await call(url, {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
      if (!response.ok) return UNAVAILABLE;
      payload = await response.json();
    } catch {
      // A thrown fetch, a resolver that never answered and the timeout gave up
      // on, a body that is not JSON: all of them are "we could not ask", never
      // "the operator has no record".
      return UNAVAILABLE;
    }

    if (typeof payload !== "object" || payload === null) return UNAVAILABLE;
    const answer = payload as Record<string, unknown>;
    const status = answer["Status"];
    if (status === DNS_RCODE_NXDOMAIN) return NXDOMAIN;
    if (status !== DNS_RCODE_NOERROR) return UNAVAILABLE;

    const records = answer["Answer"];
    const values: string[] = [];
    if (Array.isArray(records)) {
      for (const record of records) {
        if (typeof record !== "object" || record === null) continue;
        const entry = record as Record<string, unknown>;
        if (entry["type"] !== DNS_TYPE_TXT) continue;
        const data = entry["data"];
        if (typeof data !== "string") continue;
        values.push(unquote(data));
      }
    }
    // A name that resolves but carries no TXT record proves no more than a name
    // that does not resolve, and the operator's fix is the same either way.
    if (values.length === 0) return NXDOMAIN;
    return { ok: true, values };
  }
}

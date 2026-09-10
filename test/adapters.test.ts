/**
 * The three adapters that reach outside the process.
 *
 * The resolver is tested against canned dns-json bodies rather than the real
 * DNS: what is under test is how an answer is read, and a test that asked
 * Cloudflare would be testing the internet. The payout adapter is tested for
 * the one property that matters most — production's stub refuses rather than
 * passes (decision D-013 as amended). The snapshot fetcher is tested against a
 * fetch function that answers from a table, so the redirect chain, the ceiling
 * and the timeout are exercised without a single packet leaving the machine.
 */

import { describe, expect, it } from "vitest";

import {
  DNS_RCODE_NOERROR,
  DNS_RCODE_NXDOMAIN,
  DNS_TYPE_TXT,
  DOH_ENDPOINT,
  DohResolver,
} from "../src/adapters/dns.js";
import {
  DrandReader,
  FixtureBeacon,
  beaconRoundAt,
} from "../src/adapters/beacon.js";
import {
  SNAPSHOT_REQUEST_HEADERS,
  WebFetcher,
} from "../src/adapters/fetch.js";
import {
  MockPayoutAdapter,
  UnavailablePayoutAdapter,
  payoutAdapterFor,
} from "../src/adapters/payout.js";
import { sha256Hex } from "../src/hash.js";
import { BEACON, CAPTURE_MAX_BYTES, FETCH_MAX_REDIRECTS } from "../src/policy.js";

/** A fetch that answers with one canned body, remembering what it was asked. */
function cannedFetch(
  body: unknown,
  init: { status?: number; text?: string } = {},
): { fetch: typeof fetch; calls: { url: string; init?: RequestInit }[] } {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchFn = (async (url: string | URL | Request, requestInit?: RequestInit) => {
    calls.push({ url: String(url), init: requestInit });
    const text = init.text ?? JSON.stringify(body);
    return new Response(text, {
      status: init.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { fetch: fetchFn, calls };
}

const AGENT = "1F916:t2clwNKCX9MD246hQJgDKVoqhC7Q-ybl4x7xvRGWt40";

describe("DohResolver", () => {
  it("joins adjacent quoted chunks into one value", async () => {
    const { fetch } = cannedFetch({
      Status: DNS_RCODE_NOERROR,
      Answer: [
        { name: "_nomankind.example.org", type: DNS_TYPE_TXT, data: '"abc" "def"' },
      ],
    });
    const lookup = await new DohResolver(fetch).txt("_nomankind.example.org");

    expect(lookup).toEqual({ ok: true, values: ["abcdef"] });
  });

  it("returns one value per TXT answer, ignoring other record types", async () => {
    const { fetch } = cannedFetch({
      Status: DNS_RCODE_NOERROR,
      Answer: [
        { type: DNS_TYPE_TXT, data: `"v=spf1 -all"` },
        { type: DNS_TYPE_TXT, data: `"${AGENT}"` },
        // A CNAME in the same answer section is not a TXT record.
        { type: 5, data: "elsewhere.example.org." },
      ],
    });
    const lookup = await new DohResolver(fetch).txt("_nomankind.example.org");

    expect(lookup).toEqual({ ok: true, values: ["v=spf1 -all", AGENT] });
  });

  it("reads NXDOMAIN as no record", async () => {
    const { fetch } = cannedFetch({ Status: DNS_RCODE_NXDOMAIN });
    expect(await new DohResolver(fetch).txt("_nomankind.nope.example")).toEqual({
      ok: false,
      reason: "nxdomain",
    });
  });

  it("reads a name that resolves with no TXT answer as no record", async () => {
    const { fetch } = cannedFetch({ Status: DNS_RCODE_NOERROR, Answer: [] });
    expect(await new DohResolver(fetch).txt("_nomankind.example.org")).toEqual({
      ok: false,
      reason: "nxdomain",
    });
  });

  it("reads any other status as unavailable", async () => {
    // SERVFAIL: the resolver failed, which is not the operator's fault.
    const { fetch } = cannedFetch({ Status: 2 });
    expect(await new DohResolver(fetch).txt("_nomankind.example.org")).toEqual({
      ok: false,
      reason: "unavailable",
    });
  });

  it("reads a non-200 as unavailable", async () => {
    const { fetch } = cannedFetch({ Status: DNS_RCODE_NOERROR }, { status: 500 });
    expect(await new DohResolver(fetch).txt("_nomankind.example.org")).toEqual({
      ok: false,
      reason: "unavailable",
    });
  });

  it("reads a body that is not JSON as unavailable", async () => {
    const { fetch } = cannedFetch(null, { text: "<html>nope</html>" });
    expect(await new DohResolver(fetch).txt("_nomankind.example.org")).toEqual({
      ok: false,
      reason: "unavailable",
    });
  });

  it("never throws when fetch throws", async () => {
    const fetchFn = (() =>
      Promise.reject(new Error("network down"))) as unknown as typeof fetch;
    expect(await new DohResolver(fetchFn).txt("_nomankind.example.org")).toEqual({
      ok: false,
      reason: "unavailable",
    });
  });

  it("asks the DoH endpoint for the encoded name with the dns-json accept header", async () => {
    const { fetch, calls } = cannedFetch({ Status: DNS_RCODE_NXDOMAIN });
    await new DohResolver(fetch).txt("_nomankind.a b.example");

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(
      `${DOH_ENDPOINT}?name=${encodeURIComponent("_nomankind.a b.example")}&type=TXT`,
    );
    expect(calls[0].url).toContain("_nomankind.a%20b.example");
    expect(calls[0].init?.headers).toEqual({ accept: "application/dns-json" });
  });

  it("never calls fetch with the resolver itself as the receiver", async () => {
    // workerd's own fetch throws exactly this when it is called on anything but
    // the global object, and Node's does not — which is why a green suite said
    // nothing until a real registration answered dns_unavailable under
    // wrangler for a TXT record that resolves fine (the M13 lesson).
    const platformFetch = function (this: unknown): Promise<Response> {
      if (this !== undefined && this !== globalThis) {
        throw new TypeError("Illegal invocation");
      }
      return Promise.resolve(
        new Response(
          JSON.stringify({
            Status: DNS_RCODE_NOERROR,
            Answer: [{ type: DNS_TYPE_TXT, data: `"${AGENT}"` }],
          }),
          { headers: { "content-type": "application/json" } },
        ),
      );
    } as unknown as typeof fetch;

    // The record, not a swallowed unavailable: the call went through as written.
    expect(await new DohResolver(platformFetch).txt("_nomankind.example.org")).toEqual({
      ok: true,
      values: [AGENT],
    });
  });

  it("asks the endpoint it was given", async () => {
    const { fetch, calls } = cannedFetch({ Status: DNS_RCODE_NXDOMAIN });
    await new DohResolver(fetch, "https://dns.example/query").txt("_nomankind.x.example");

    expect(calls[0].url.startsWith("https://dns.example/query?")).toBe(true);
  });
});

describe("payout adapters", () => {
  it("reads the mock's three prefixes", async () => {
    const mock = new MockPayoutAdapter();
    expect(await mock.status("mock-verified-abc")).toBe("verified");
    expect(await mock.status("mock-pending-abc")).toBe("pending");
    expect(await mock.status("anything-else")).toBe("failed");
  });

  it("refuses rather than passes when no provider is wired", async () => {
    expect(await new UnavailablePayoutAdapter().status("mock-verified-abc")).toBe(
      "unavailable",
    );
  });

  it("transfers only for a reference it would also call verified", async () => {
    const mock = new MockPayoutAdapter();
    const first = await mock.transfer("mock-verified-abc", 5_000_000);
    expect(first).toEqual({ ok: true, transfer: "mock-transfer-1" });
    // A counter, so a demo can tell two transfers apart.
    expect(await mock.transfer("mock-verified-abc", 1)).toEqual({
      ok: true,
      transfer: "mock-transfer-2",
    });
    // Pending onboarding is not payable: the mock must not pay an operator it
    // has just said the provider is still checking.
    expect(await mock.transfer("mock-pending-abc", 1)).toEqual({
      ok: false,
      reason: "failed",
    });
    expect(await mock.transfer("anything-else", 1)).toEqual({
      ok: false,
      reason: "failed",
    });
  });

  it("says nothing left rather than that it failed, when nothing was wired", async () => {
    // "unavailable" and never "failed": the cycle that meets this carries the
    // accrual forward untouched, where a failure would say it was refused.
    expect(
      await new UnavailablePayoutAdapter().transfer("mock-verified-abc", 5_000_000),
    ).toEqual({ ok: false, reason: "unavailable" });
  });

  it("gives production the unavailable stub and everything else the mock", () => {
    expect(payoutAdapterFor("production")).toBeInstanceOf(UnavailablePayoutAdapter);
    expect(payoutAdapterFor("demo")).toBeInstanceOf(MockPayoutAdapter);
    expect(payoutAdapterFor("local")).toBeInstanceOf(MockPayoutAdapter);
  });
});

/**
 * The capture fetch, step 1 of the norm rule.
 *
 * Every response below is canned. What is under test is the rule: the four
 * fixed headers go out, the chain is followed by hand and counted, the final
 * URL is the one the bytes came from, and each of the five refusals is reached
 * by the thing that causes it.
 */
describe("WebFetcher", () => {
  const PAGE = "<!doctype html><html><body><p>ok</p></body></html>";

  /** A fetch answering from a table of URLs, remembering what it was asked. */
  function tableFetch(pages: Record<string, () => Response>): {
    fetch: typeof fetch;
    calls: { url: string; init: RequestInit }[];
  } {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchFn = (async (url: string | URL | Request, init?: RequestInit) => {
      const key = String(url);
      calls.push({ url: key, init: init ?? {} });
      const page = pages[key];
      if (page === undefined) throw new TypeError(`no route for ${key}`);
      return page();
    }) as unknown as typeof fetch;
    return { fetch: fetchFn, calls };
  }

  function html(body = PAGE, init: ResponseInit = {}): Response {
    return new Response(body, {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
      ...init,
    });
  }

  function redirect(to: string, status = 302): Response {
    return new Response(null, { status, headers: { location: to } });
  }

  it("sends the norm rule's four fixed headers, and follows nothing itself", async () => {
    const { fetch, calls } = tableFetch({ "https://example.org/p": () => html() });
    const result = await new WebFetcher(fetch).fetch("https://example.org/p");

    expect(result.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.init.method).toBe("GET");
    expect(calls[0]!.init.redirect).toBe("manual");
    expect(calls[0]!.init.headers).toEqual({ ...SNAPSHOT_REQUEST_HEADERS });
  });

  it("never calls fetch with the fetcher itself as the receiver", async () => {
    // workerd's own fetch throws exactly this when it is called on anything but
    // the global object, and Node's does not — which is why a green suite said
    // nothing until a real submission answered fetch_failed under wrangler.
    const platformFetch = function (this: unknown): Promise<Response> {
      if (this !== undefined && this !== globalThis) {
        throw new TypeError("Illegal invocation");
      }
      return Promise.resolve(html());
    } as unknown as typeof fetch;

    const result = await new WebFetcher(platformFetch).fetch(
      "https://example.org/p",
    );

    // ok, not a swallowed fetch_failed: the call went through as written.
    expect(result).toMatchObject({ ok: true, status: 200 });
  });

  it("returns the body, the status and the response headers", async () => {
    const { fetch } = tableFetch({ "https://example.org/p": () => html() });
    const result = await new WebFetcher(fetch).fetch("https://example.org/p");

    expect(result).toMatchObject({
      ok: true,
      status: 200,
      finalUrl: "https://example.org/p",
    });
    if (!result.ok) throw new Error("expected a capture");
    expect(new TextDecoder().decode(result.bytes)).toBe(PAGE);
    expect(result.headers["content-type"]).toBe("text/html; charset=utf-8");
  });

  it("records no set-cookie, whatever the page sends", async () => {
    const { fetch } = tableFetch({
      "https://example.org/p": () =>
        html(PAGE, {
          headers: { "content-type": "text/html", "set-cookie": "a=b" },
        }),
    });
    const result = await new WebFetcher(fetch).fetch("https://example.org/p");

    if (!result.ok) throw new Error("expected a capture");
    expect(Object.keys(result.headers)).not.toContain("set-cookie");
  });

  it("follows two hops and records the final URL", async () => {
    const { fetch, calls } = tableFetch({
      "https://example.org/a": () => redirect("/b", 301),
      "https://example.org/b": () => redirect("https://cdn.example.org/c", 308),
      "https://cdn.example.org/c": () => html(),
    });
    const result = await new WebFetcher(fetch).fetch("https://example.org/a");

    expect(calls.map((call) => call.url)).toEqual([
      "https://example.org/a",
      "https://example.org/b",
      "https://cdn.example.org/c",
    ]);
    expect(result).toMatchObject({
      ok: true,
      finalUrl: "https://cdn.example.org/c",
    });
  });

  it("follows five redirects and refuses the sixth", async () => {
    const pages: Record<string, () => Response> = {};
    for (let hop = 0; hop <= FETCH_MAX_REDIRECTS + 1; hop += 1) {
      pages[`https://example.org/${hop}`] = () =>
        redirect(`https://example.org/${hop + 1}`);
    }
    const last = FETCH_MAX_REDIRECTS;
    const withinLimit = tableFetch({
      ...pages,
      [`https://example.org/${last}`]: () => html(),
    });
    expect(
      await new WebFetcher(withinLimit.fetch).fetch("https://example.org/0"),
    ).toMatchObject({ ok: true, finalUrl: `https://example.org/${last}` });

    const overLimit = tableFetch(pages);
    expect(
      await new WebFetcher(overLimit.fetch).fetch("https://example.org/0"),
    ).toEqual({ ok: false, reason: "too_many_redirects" });
  });

  it("refuses a redirect off http entirely", async () => {
    const { fetch } = tableFetch({
      "https://example.org/a": () => redirect("ftp://example.org/file"),
    });
    expect(
      await new WebFetcher(fetch).fetch("https://example.org/a"),
    ).toEqual({ ok: false, reason: "fetch_failed" });
  });

  it("refuses a body that declares itself too large, without reading it", async () => {
    const { fetch } = tableFetch({
      "https://example.org/big": () =>
        new Response("small in fact", {
          status: 200,
          headers: {
            "content-type": "text/plain",
            "content-length": String(CAPTURE_MAX_BYTES + 1),
          },
        }),
    });
    expect(
      await new WebFetcher(fetch).fetch("https://example.org/big"),
    ).toEqual({ ok: false, reason: "too_large" });
  });

  it("refuses a status outside 200 to 299", async () => {
    const { fetch } = tableFetch({
      "https://example.org/gone": () => new Response("nope", { status: 404 }),
    });
    expect(
      await new WebFetcher(fetch).fetch("https://example.org/gone"),
    ).toEqual({ ok: false, reason: "bad_status" });
  });

  it("reports a fetch that throws as a failed fetch, never as a crash", async () => {
    const thrower = (() =>
      Promise.reject(new TypeError("network"))) as unknown as typeof fetch;
    expect(
      await new WebFetcher(thrower).fetch("https://example.org/p"),
    ).toEqual({ ok: false, reason: "fetch_failed" });
  });

  it("refuses a citation that is not an http URL", async () => {
    const { fetch } = tableFetch({});
    expect(await new WebFetcher(fetch).fetch("mailto:someone@example.org")).toEqual(
      { ok: false, reason: "fetch_failed" },
    );
  });

  it("times out a fetch that never answers", async () => {
    const hung = ((_url: unknown, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new Error("aborted")),
        );
      })) as unknown as typeof fetch;

    // A small injected window: the default is the policy number, and a test
    // that waited for it would wait thirty seconds.
    expect(await new WebFetcher(hung, 5).fetch("https://example.org/hang")).toEqual({
      ok: false,
      reason: "timeout",
    });
  });
});

/**
 * The beacon the draw reads.
 *
 * Every case runs against a fetch that answers from memory: what is under test
 * is whether a round is believed, not whether drand is up. The signature and its
 * randomness are real — the randomness is the SHA-256 of the signature bytes, as
 * drand defines it — so the round the reader accepts is one the real check
 * passes rather than one the fixture was allowed to skip.
 */
describe("DrandReader", () => {
  const LATEST_URL = `${BEACON.endpoint}/${BEACON.chain_hash}/public/latest`;
  const SIGNATURE = "b4".repeat(48);
  const ROUND = 4_100_100;

  /** The randomness a real chain would publish for that signature. */
  async function randomnessOf(signatureHex: string): Promise<string> {
    const bytes = new Uint8Array(signatureHex.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Number.parseInt(
        signatureHex.slice(index * 2, index * 2 + 2),
        16,
      );
    }
    return sha256Hex(bytes);
  }

  /** A round the reader should accept. */
  async function goodRound(round = ROUND): Promise<{
    round: number;
    randomness: string;
    signature: string;
  }> {
    return {
      round,
      randomness: await randomnessOf(SIGNATURE),
      signature: SIGNATURE,
    };
  }

  /** A fetch that answers one canned body, remembering what it was asked. */
  function beaconFetch(
    body: unknown,
    init: { status?: number; text?: string } = {},
  ): { fetch: typeof fetch; calls: string[] } {
    const calls: string[] = [];
    const fetchFn = (async (url: string | URL | Request) => {
      calls.push(String(url));
      return new Response(init.text ?? JSON.stringify(body), {
        status: init.status ?? 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;
    return { fetch: fetchFn, calls };
  }

  it("reads the pinned chain's latest round and times it from genesis", async () => {
    const { fetch, calls } = beaconFetch(await goodRound());
    const result = await new DrandReader(fetch).latest();

    expect(calls).toEqual([LATEST_URL]);
    expect(result).toEqual({
      ok: true,
      beacon: {
        round: ROUND,
        randomness: await randomnessOf(SIGNATURE),
        at: new Date(
          (BEACON.genesis_time + (ROUND - 1) * BEACON.period_seconds) * 1000,
        ).toISOString(),
      },
    });
  });

  it("times round one at the chain's genesis", async () => {
    expect(beaconRoundAt(1)).toBe(
      new Date(BEACON.genesis_time * 1000).toISOString(),
    );
    expect(Date.parse(beaconRoundAt(2)) - Date.parse(beaconRoundAt(1))).toBe(
      BEACON.period_seconds * 1000,
    );
  });

  it("never calls fetch with the reader itself as the receiver", async () => {
    // workerd's own fetch throws exactly this when it is called on anything but
    // the global object, and Node's does not (the M13 lesson).
    const round = await goodRound();
    const platformFetch = function (this: unknown): Promise<Response> {
      if (this !== undefined && this !== globalThis) {
        throw new TypeError("Illegal invocation");
      }
      return Promise.resolve(new Response(JSON.stringify(round)));
    } as unknown as typeof fetch;

    // ok, not a swallowed beacon_unavailable: the call went through as written.
    expect(await new DrandReader(platformFetch).latest()).toMatchObject({
      ok: true,
    });
  });

  it("reads a non-2xx as unavailable", async () => {
    const { fetch } = beaconFetch(await goodRound(), { status: 503 });
    expect(await new DrandReader(fetch).latest()).toEqual({
      ok: false,
      reason: "beacon_unavailable",
    });
  });

  it("reads a body that is not JSON as unavailable", async () => {
    const { fetch } = beaconFetch(null, { text: "<html>down</html>" });
    expect(await new DrandReader(fetch).latest()).toEqual({
      ok: false,
      reason: "beacon_unavailable",
    });
  });

  it("never throws when fetch throws", async () => {
    const throwing = (() => {
      throw new TypeError("network down");
    }) as unknown as typeof fetch;
    expect(await new DrandReader(throwing).latest()).toEqual({
      ok: false,
      reason: "beacon_unavailable",
    });
  });

  it("refuses a round that is not a positive integer", async () => {
    const good = await goodRound();
    for (const round of [0, -1, 1.5, "4100100", null]) {
      const { fetch } = beaconFetch({ ...good, round });
      expect(await new DrandReader(fetch).latest()).toEqual({
        ok: false,
        reason: "bad_beacon",
      });
    }
  });

  it("refuses randomness that is not 64 lowercase hex characters", async () => {
    const good = await goodRound();
    for (const randomness of [
      good.randomness.toUpperCase(),
      good.randomness.slice(0, 63),
      `${good.randomness}00`,
      123,
    ]) {
      const { fetch } = beaconFetch({ ...good, randomness });
      expect(await new DrandReader(fetch).latest()).toEqual({
        ok: false,
        reason: "bad_beacon",
      });
    }
  });

  it("refuses a round whose randomness is not the hash of its signature", async () => {
    // The check that makes the draw unsteerable: a server handing out an
    // invented randomness could pick the validator, and this is what stops it.
    const good = await goodRound();
    const { fetch } = beaconFetch({
      ...good,
      randomness: await randomnessOf("c5".repeat(48)),
    });
    expect(await new DrandReader(fetch).latest()).toEqual({
      ok: false,
      reason: "bad_beacon",
    });
  });

  it("refuses a signature that is not whole lowercase hex", async () => {
    const good = await goodRound();
    for (const signature of [`${SIGNATURE}b`, SIGNATURE.toUpperCase(), "zz", 7]) {
      const { fetch } = beaconFetch({ ...good, signature });
      expect(await new DrandReader(fetch).latest()).toEqual({
        ok: false,
        reason: "bad_beacon",
      });
    }
  });
});

describe("FixtureBeacon", () => {
  const AT = "2026-09-01T01:00:00.000Z";

  it("has nothing to give before the first advance", async () => {
    expect(await new FixtureBeacon("seed").latest()).toEqual({
      ok: false,
      reason: "beacon_unavailable",
    });
  });

  it("counts rounds from one and hands back the newest", async () => {
    const beacon = new FixtureBeacon("seed");
    const first = await beacon.advance(AT);
    expect(first.round).toBe(1);
    expect(first.at).toBe(AT);
    expect(await beacon.latest()).toEqual({ ok: true, beacon: first });

    const second = await beacon.advance("2026-09-01T02:00:00.000Z");
    expect(second.round).toBe(2);
    expect(await beacon.latest()).toEqual({ ok: true, beacon: second });
  });

  it("gives 64 hex characters of randomness, seeded and repeatable", async () => {
    const first = await new FixtureBeacon("seed").advance(AT);
    const again = await new FixtureBeacon("seed").advance(AT);
    const other = await new FixtureBeacon("other").advance(AT);

    expect(first.randomness).toMatch(/^[0-9a-f]{64}$/);
    expect(first.randomness).toBe(await sha256Hex("seed:1"));
    expect(again).toEqual(first);
    expect(other.randomness).not.toBe(first.randomness);
  });
});

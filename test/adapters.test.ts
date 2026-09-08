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
  SNAPSHOT_REQUEST_HEADERS,
  WebFetcher,
} from "../src/adapters/fetch.js";
import {
  MockPayoutAdapter,
  UnavailablePayoutAdapter,
  payoutAdapterFor,
} from "../src/adapters/payout.js";
import { CAPTURE_MAX_BYTES, FETCH_MAX_REDIRECTS } from "../src/policy.js";

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

/**
 * The two adapters that reach outside the process.
 *
 * The resolver is tested against canned dns-json bodies rather than the real
 * DNS: what is under test is how an answer is read, and a test that asked
 * Cloudflare would be testing the internet. The payout adapter is tested for
 * the one property that matters most — production's stub refuses rather than
 * passes (decision D-013 as amended).
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
  MockPayoutAdapter,
  UnavailablePayoutAdapter,
  payoutAdapterFor,
} from "../src/adapters/payout.js";

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

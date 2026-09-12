/**
 * The two adapters that had no timeout (the QA of 2026-09-12).
 *
 * Every other outbound call in the system is bounded by src/policy.ts's
 * FETCH_TIMEOUT_MS — the mirror, the payment provider, the witnesses, the
 * calendar, the citation fetcher — and these two were not. A DNS resolver that
 * accepts the connection and never answers held the registration door open; a
 * drand endpoint that did the same held the whole sweep open behind the draw,
 * and every step under it with it. Neither is a hypothetical: an endpoint that
 * hangs rather than refusing is the ordinary shape of a bad afternoon.
 *
 * The window is injected small here rather than waited out, exactly as
 * WebFetcher's own timeout test does it (test/adapters.test.ts): the default is
 * the policy number, and a test that waited for it would wait thirty seconds.
 * What is under test is that the call is bounded at all and that the bound
 * answers in the adapter's own words — `unavailable` and `beacon_unavailable`,
 * the two the callers already know how to act on — rather than throwing
 * something neither caller handles.
 */

import { describe, expect, it } from "vitest";

import { DrandReader } from "../src/adapters/beacon.js";
import { DohResolver } from "../src/adapters/dns.js";
import { FETCH_TIMEOUT_MS } from "../src/policy.js";

/** A small window, so a hung endpoint is watched rather than waited for. */
const WINDOW_MS = 5;

/**
 * A fetch that never answers on its own: it settles only when the signal it was
 * handed aborts, which is what the platform's own fetch does and the only thing
 * a timeout can be observed through.
 */
function hungFetch(seen: { signal: AbortSignal | null }): typeof fetch {
  return ((_url: unknown, init?: RequestInit) =>
    new Promise<Response>((_resolve, reject) => {
      seen.signal = init?.signal ?? null;
      init?.signal?.addEventListener("abort", () =>
        reject(new Error("aborted")),
      );
    })) as unknown as typeof fetch;
}

describe("the DNS-over-HTTPS resolver's timeout", () => {
  it("answers unavailable rather than hanging on a resolver that never replies", async () => {
    const seen = { signal: null as AbortSignal | null };
    const resolver = new DohResolver(
      hungFetch(seen),
      "https://dns.example/query",
      WINDOW_MS,
    );

    expect(await resolver.txt("_nomankind.example.org")).toEqual({
      ok: false,
      reason: "unavailable",
    });
    // Bounded by a signal and not by luck: the caller sees the same abort the
    // platform's fetch would have raised.
    expect(seen.signal).toBeInstanceOf(AbortSignal);
    expect(seen.signal?.aborted).toBe(true);
  });

  it("carries a signal on a lookup that answers, with no window given", async () => {
    const seen = { signal: null as AbortSignal | null };
    const answering = ((_url: unknown, init?: RequestInit) => {
      seen.signal = init?.signal ?? null;
      return Promise.resolve(
        new Response(JSON.stringify({ Status: 3 }), { status: 200 }),
      );
    }) as unknown as typeof fetch;

    // The default window is the policy number and nothing local to the adapter.
    expect(FETCH_TIMEOUT_MS).toBeGreaterThan(0);
    expect(await new DohResolver(answering).txt("_nomankind.example.org")).toEqual({
      ok: false,
      reason: "nxdomain",
    });
    expect(seen.signal).toBeInstanceOf(AbortSignal);
    expect(seen.signal?.aborted).toBe(false);
  });
});

describe("the drand reader's timeout", () => {
  it("answers beacon_unavailable rather than hanging on a chain that never replies", async () => {
    const seen = { signal: null as AbortSignal | null };
    const reader = new DrandReader(hungFetch(seen), WINDOW_MS);

    expect(await reader.latest()).toEqual({
      ok: false,
      reason: "beacon_unavailable",
    });
    expect(seen.signal).toBeInstanceOf(AbortSignal);
    expect(seen.signal?.aborted).toBe(true);
  });

  it("carries a signal on a read that answers, with no window given", async () => {
    const seen = { signal: null as AbortSignal | null };
    const answering = ((_url: unknown, init?: RequestInit) => {
      seen.signal = init?.signal ?? null;
      // Not a round the check believes, which is beside the point here: what is
      // under test is that the call went out bounded and came back.
      return Promise.resolve(new Response("{}", { status: 200 }));
    }) as unknown as typeof fetch;

    expect(await new DrandReader(answering).latest()).toEqual({
      ok: false,
      reason: "bad_beacon",
    });
    expect(seen.signal).toBeInstanceOf(AbortSignal);
    expect(seen.signal?.aborted).toBe(false);
  });
});

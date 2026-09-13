/**
 * The four files a crawler reads (decision D-114), through the real router.
 *
 * Whitepaper Section 11: two environments, and the pages script-free. That is
 * the whole of what these routes have to respect — demo is a rehearsal and must
 * not be indexed at all, the apex serves one page and the app serves the log, and
 * nothing here may add a script, a font or an image from anywhere else. So the
 * icon is bytes this Worker draws, the sitemap is built from the same store the
 * pages are rendered from, and robots.txt says which of the two environments a
 * crawler is standing in.
 *
 * The store is miniflare's D1, the same engine Cloudflare runs, and the rows are
 * inserted directly: the sitemap reads two columns per entry and nothing else,
 * and a world built through the submit and validate doors would be several
 * hundred events to check a URL list. The bound on that list is checked against a
 * store that never runs out of rows, which is the only way to see that the
 * document stops where policy says it does.
 */

import { describe, expect, it, afterAll, beforeAll } from "vitest";

import { LIST_PAGE_LIMIT, SITEMAP_MAX_ENTRIES } from "../src/policy.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import { putOperator } from "../src/storage/repository.js";
import { FAVICON_ACCENT, FAVICON_BACKGROUND } from "../src/ui/favicon.js";
import { APP_CSS_HREF } from "../src/ui/html.js";
import { LANDING_CSS_HREF } from "../src/ui/pages/landing.js";
import type { Env } from "../src/worker/env.js";
import { cacheablePath, handleRequest } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const NOW = new Date("2026-09-13T00:00:00.000Z");

/** The two hostnames production routes, and the one a preview is reached at. */
const APEX_HOST = "nomankind.ai";
const APP_HOST = "app.nomankind.ai";
const APEX_ORIGIN = `https://${APEX_HOST}`;
const APP_ORIGIN = `https://${APP_HOST}`;
const PREVIEW_ORIGIN = "https://nomankind-abc123.workers.dev";

const HTML = { accept: "text/html,application/xhtml+xml" };

/** The preload the pages ask for, in the one form the route writes it. */
function expectedLink(sheet: string): string {
  return `<${sheet}>; rel=preload; as=style, <https://fonts.googleapis.com>; rel=preconnect`;
}

let store: TestDatabase;

function envWith(vars: Partial<Env> = {}, db: D1Like = store.db): Env {
  return {
    DB: db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
    ...vars,
  } as unknown as Env;
}

function get(
  url: string,
  env: Env,
  init: RequestInit = {},
): Promise<Response> {
  return handleRequest(new Request(url, init), env, { now: NOW });
}

/** One entry row, as the two columns the sitemap reads care about. */
async function seedEntry(
  id: string,
  submittedAt: string,
  seq: number,
): Promise<void> {
  await store.db
    .prepare(
      `INSERT INTO entries (
         id, subject, category, status, submitted_at, submitted_seq,
         author, entry_json, sidecar_json, derived_through_seq
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      id,
      "example/kestrel-1",
      "pricing",
      "verified",
      submittedAt,
      seq,
      "1F916:author",
      "{}",
      "{}",
      seq,
    )
    .run();
}

/** Three entries around the first page boundary, at MAX-1, MAX and MAX+1. */
const ENTRY_BEFORE_BOUNDARY = "nmk_00000000000000000000000000000d41";
const ENTRY_ON_BOUNDARY = "nmk_00000000000000000000000000000e52";
const ENTRY_AFTER_BOUNDARY = "nmk_00000000000000000000000000000f63";

const ENTRY_OLDEST = "nmk_000000000000000000000000000000a1";
const ENTRY_MIDDLE = "nmk_000000000000000000000000000000b2";
const ENTRY_NEWEST = "nmk_000000000000000000000000000000c3";
/** An operator id carrying two characters XML would otherwise read as markup. */
const AWKWARD_OPERATOR = "a&b<c.example";

beforeAll(async () => {
  store = await openTestDatabase();
  await seedEntry(ENTRY_OLDEST, "2026-09-01T10:15:00.000Z", 1);
  await seedEntry(ENTRY_MIDDLE, "2026-09-05T23:59:59.000Z", 2);
  await seedEntry(ENTRY_NEWEST, "2026-09-11T08:00:00.000Z", 3);
  await seedEntry(
    ENTRY_BEFORE_BOUNDARY,
    "2026-09-12T01:00:00.000Z",
    SITEMAP_MAX_ENTRIES - 1,
  );
  await seedEntry(ENTRY_ON_BOUNDARY, "2026-09-12T02:00:00.000Z", SITEMAP_MAX_ENTRIES);
  await seedEntry(
    ENTRY_AFTER_BOUNDARY,
    "2026-09-12T03:00:00.000Z",
    SITEMAP_MAX_ENTRIES + 1,
  );
  for (const [index, id] of ["k1.example", "k2.example", AWKWARD_OPERATOR].entries()) {
    await putOperator(store.db, {
      id,
      maintainer: false,
      provider: false,
      registeredSeq: index,
      details: {},
    });
  }
}, 120_000);

afterAll(async () => {
  await store.dispose();
});

// ---------------------------------------------------------------------------
// robots.txt
// ---------------------------------------------------------------------------

describe("GET /robots.txt", () => {
  it("closes demo to crawlers outright", async () => {
    const response = await get(
      `${APP_ORIGIN}/robots.txt`,
      envWith({ ENVIRONMENT: "demo", APP_HOST }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(
      "text/plain; charset=utf-8",
    );
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    // A rehearsal with throwaway keys is a copy of the record that is not the
    // record, so no sitemap is offered either.
    expect(await response.text()).toBe("User-agent: *\nDisallow: /\n");
  }, 60_000);

  it("opens the app and names its own sitemap", async () => {
    const response = await get(
      `${APP_ORIGIN}/robots.txt`,
      envWith({ ENVIRONMENT: "production", APEX_HOST, APP_HOST }),
    );
    expect(await response.text()).toBe(
      `User-agent: *\nAllow: /\nSitemap: ${APP_ORIGIN}/sitemap.xml\n`,
    );
  }, 60_000);

  it("names the configured host even when reached at another one", async () => {
    // A preview URL answers the same log; a crawler that found it is sent to
    // the sitemap of the host this deployment calls its own.
    const response = await get(
      `${PREVIEW_ORIGIN}/robots.txt`,
      envWith({ ENVIRONMENT: "production", APEX_HOST, APP_HOST }),
    );
    expect(await response.text()).toContain(`Sitemap: ${APP_ORIGIN}/sitemap.xml`);
  }, 60_000);

  it("names the apex's own sitemap on the apex", async () => {
    const response = await get(
      `${APEX_ORIGIN}/robots.txt`,
      envWith({ ENVIRONMENT: "production", APEX_HOST, APP_HOST }),
    );
    expect(await response.text()).toBe(
      `User-agent: *\nAllow: /\nSitemap: ${APEX_ORIGIN}/sitemap.xml\n`,
    );
  }, 60_000);

  it("falls back to the request's own origin when no host is configured", async () => {
    // Local's situation: whatever host the developer typed, because a sitemap
    // URL on a hostname nobody routes is worse than none.
    const response = await get(`${PREVIEW_ORIGIN}/robots.txt`, envWith());
    expect(await response.text()).toContain(
      `Sitemap: ${PREVIEW_ORIGIN}/sitemap.xml`,
    );
  }, 60_000);

  it("answers a HEAD with the same headers and no body", async () => {
    const env = envWith({ APP_HOST });
    const head = await get(`${APP_ORIGIN}/robots.txt`, env, { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(head.body).toBeNull();
    expect(head.headers.get("content-type")).toBe("text/plain; charset=utf-8");
  }, 60_000);

  it("refuses a wrong method with the handlers' own envelope", async () => {
    const response = await get(`${APP_ORIGIN}/robots.txt`, envWith(), {
      method: "PUT",
    });
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toContain("GET");
  }, 60_000);
});

// ---------------------------------------------------------------------------
// sitemap.xml
// ---------------------------------------------------------------------------

/** Every `<loc>` of a sitemap, in the order the document lists them. */
function locations(xml: string): string[] {
  return [...xml.matchAll(/<loc>([^<]*)<\/loc>/g)].map((match) => match[1]!);
}

describe("GET /sitemap.xml", () => {
  const production = () =>
    envWith({ ENVIRONMENT: "production", APEX_HOST, APP_HOST });

  it("lists the static pages, absolute on the canonical origin", async () => {
    const response = await get(`${APP_ORIGIN}/sitemap.xml`, production());
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(
      "application/xml; charset=utf-8",
    );
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    const xml = await response.text();
    expect(xml.startsWith(`<?xml version="1.0" encoding="UTF-8"?>`)).toBe(true);
    expect(xml).toContain(
      `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`,
    );
    expect(xml.trimEnd().endsWith("</urlset>")).toBe(true);

    const found = locations(xml);
    for (const path of [
      "/",
      "/entries",
      "/domains",
      "/operators",
      "/policy",
      "/api",
      "/genesis",
      "/dry-run",
      "/how-it-works",
      "/status",
      "/docs",
      "/docs/fork",
      "/docs/whitepaper",
      "/docs/summary",
      "/mirror/latest",
    ]) {
      expect(found, path).toContain(`${APP_ORIGIN}${path}`);
    }
  }, 60_000);

  it("names every registered operator", async () => {
    const found = locations(
      await (await get(`${APP_ORIGIN}/sitemap.xml`, production())).text(),
    );
    expect(found).toContain(`${APP_ORIGIN}/operators/k1.example`);
    expect(found).toContain(`${APP_ORIGIN}/operators/k2.example`);
  }, 60_000);

  it("names every entry newest first, with the date it was submitted", async () => {
    const xml = await (
      await get(`${APP_ORIGIN}/sitemap.xml`, production())
    ).text();
    const found = locations(xml);
    const order = [ENTRY_NEWEST, ENTRY_MIDDLE, ENTRY_OLDEST].map((id) =>
      found.indexOf(`${APP_ORIGIN}/entries/${id}`),
    );
    for (const index of order) expect(index).toBeGreaterThan(-1);
    expect(order[0]!).toBeLessThan(order[1]!);
    expect(order[1]!).toBeLessThan(order[2]!);

    // The date half of the stored instant, taken from the row and not a clock.
    expect(xml).toContain(
      `<loc>${APP_ORIGIN}/entries/${ENTRY_NEWEST}</loc><lastmod>2026-09-11</lastmod>`,
    );
    expect(xml).toContain(
      `<loc>${APP_ORIGIN}/entries/${ENTRY_MIDDLE}</loc><lastmod>2026-09-05</lastmod>`,
    );
    // A static page is not a record and carries no date of its own.
    expect(xml).toContain(`<loc>${APP_ORIGIN}/policy</loc></url>`);
  }, 60_000);

  it("escapes everything XML gives meaning to", async () => {
    const xml = await (
      await get(`${APP_ORIGIN}/sitemap.xml`, production())
    ).text();
    // The operator id carrying `&` and `<` is a URL before it is XML, so it is
    // percent-encoded; what must never appear is either character raw.
    expect(xml).toContain(`${APP_ORIGIN}/operators/a%26b%3Cc.example`);
    expect(xml).not.toContain("a&b<c.example");
    expect(/&(?!amp;|lt;|gt;|quot;|apos;|#)/.test(xml)).toBe(false);
    expect(xml.replace(/<\/?[a-z?][^>]*>/g, "")).not.toContain("<");
  }, 60_000);

  it("is one line on the apex, which serves one page", async () => {
    const xml = await (
      await get(`${APEX_ORIGIN}/sitemap.xml`, production())
    ).text();
    expect(locations(xml)).toEqual([`${APEX_ORIGIN}/`]);
    // The log lives on the app; naming its paths under the apex's own host is
    // how one record becomes two indexed copies of itself.
    expect(xml).not.toContain("/entries/");
  }, 60_000);

  it("answers a HEAD with the same headers and no body", async () => {
    const head = await get(`${APP_ORIGIN}/sitemap.xml`, production(), {
      method: "HEAD",
    });
    expect(head.status).toBe(200);
    expect(head.body).toBeNull();
    expect(head.headers.get("content-type")).toBe(
      "application/xml; charset=utf-8",
    );
  }, 60_000);
});

/**
 * A store that never runs out of entries, for the one thing a fixture cannot
 * show: that the document stops at SITEMAP_MAX_ENTRIES however long the log is.
 *
 * Every entries query is answered with exactly as many rows as it asked for, so
 * the keyset loop would page forever if the bound were not applied, and every
 * limit the route bound is recorded so the reads can be seen to be query-shaped
 * rather than a scan.
 */
function endlessEntries(): { db: D1Like; limits: () => number[] } {
  const limits: number[] = [];
  let minted = 0;
  const make = (sql: string): D1LikeStatement => {
    let bound: unknown[] = [];
    const statement = {
      bind: (...args: unknown[]) => {
        bound = args;
        if (/FROM entries/i.test(sql)) limits.push(Number(args[args.length - 1]));
        return statement;
      },
      first: () => Promise.resolve(null),
      run: () => Promise.resolve({ results: [], success: true }),
      all: () => {
        if (!/FROM entries/i.test(sql)) {
          return Promise.resolve({ results: [], success: true });
        }
        const limit = Number(bound[bound.length - 1]);
        const results = Array.from({ length: limit }, () => {
          minted += 1;
          return {
            id: `nmk_${String(minted).padStart(32, "0")}`,
            submitted_at: "2026-09-01T00:00:00.000Z",
            submitted_seq: 1_000_000 - minted,
          };
        });
        return Promise.resolve({ results, success: true });
      },
    } as unknown as D1LikeStatement;
    return statement;
  };
  const db: D1Like = {
    prepare: (sql: string) => make(sql),
    batch: () => Promise.resolve([]),
    exec: () => Promise.resolve({ count: 0, duration: 0 }),
  };
  return { db, limits: () => limits };
}

describe("the sitemap's bound", () => {
  const endlessEnv = (db: D1Like) =>
    envWith({ ENVIRONMENT: "production", APEX_HOST, APP_HOST }, db);

  it("answers an index once the log outgrows one document", async () => {
    const endless = endlessEntries();
    const response = await get(`${APP_ORIGIN}/sitemap.xml`, endlessEnv(endless.db));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(
      "application/xml; charset=utf-8",
    );
    const xml = await response.text();

    // The index names documents and no pages of its own: a crawler that follows
    // it reads the whole log, which is the point of it existing at all.
    expect(xml).toContain(
      `<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`,
    );
    expect(xml.trimEnd().endsWith("</sitemapindex>")).toBe(true);
    expect(xml).not.toContain("<urlset");
    expect(xml).not.toContain("/entries/");

    const named = locations(xml);
    expect(named[0]).toBe(`${APP_ORIGIN}/sitemap-pages.xml`);
    // The fixture's newest position is one below a million, so the sequence
    // space needs exactly that many pages of the published width.
    const pages = Math.floor(999_999 / SITEMAP_MAX_ENTRIES) + 1;
    expect(named).toHaveLength(pages + 1);
    expect(named[1]).toBe(`${APP_ORIGIN}/sitemap-entries-1.xml`);
    expect(named[named.length - 1]).toBe(
      `${APP_ORIGIN}/sitemap-entries-${pages}.xml`,
    );

    // And the walk that decided it was keyed and limited: no page asked for
    // more than the list page size, and the last asked for what was left of the
    // bound. Nothing here read the whole table to find out it was too big.
    const asked = endless.limits();
    expect(asked.length).toBeGreaterThan(1);
    for (const limit of asked) expect(limit).toBeLessThanOrEqual(LIST_PAGE_LIMIT);
    expect(asked.reduce((total, limit) => total + limit, 0)).toBe(
      SITEMAP_MAX_ENTRIES,
    );
  }, 60_000);

  it("never names more entries on one page than policy publishes", async () => {
    const endless = endlessEntries();
    const xml = await (
      await get(`${APP_ORIGIN}/sitemap-entries-1.xml`, endlessEnv(endless.db))
    ).text();
    const entryUrls = [...xml.matchAll(/<loc>[^<]*\/entries\/[^<]*<\/loc>/g)];
    expect(entryUrls).toHaveLength(SITEMAP_MAX_ENTRIES);

    const asked = endless.limits();
    expect(asked.length).toBeGreaterThan(1);
    for (const limit of asked) expect(limit).toBeLessThanOrEqual(LIST_PAGE_LIMIT);
    expect(asked.reduce((total, limit) => total + limit, 0)).toBe(
      SITEMAP_MAX_ENTRIES,
    );
  }, 60_000);
});

// ---------------------------------------------------------------------------
// The documents the index names
// ---------------------------------------------------------------------------

describe("the sitemap's own pages", () => {
  const production = () =>
    envWith({ ENVIRONMENT: "production", APEX_HOST, APP_HOST });

  it("puts the static pages and the operators in one document", async () => {
    const response = await get(`${APP_ORIGIN}/sitemap-pages.xml`, production());
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(
      "application/xml; charset=utf-8",
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
    const xml = await response.text();
    const found = locations(xml);
    expect(found).toContain(`${APP_ORIGIN}/`);
    expect(found).toContain(`${APP_ORIGIN}/policy`);
    expect(found).toContain(`${APP_ORIGIN}/operators/k1.example`);
    // The log is the other half, and it is on the entry pages.
    expect(xml).not.toContain("/entries/");
  }, 60_000);

  it("carries every entry of its own fixed range, and its dates", async () => {
    const xml = await (
      await get(`${APP_ORIGIN}/sitemap-entries-1.xml`, production())
    ).text();
    expect(xml).toContain(
      `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`,
    );
    // The three seeded entries sit at positions 1 to 3, which is page one.
    for (const id of [ENTRY_OLDEST, ENTRY_MIDDLE, ENTRY_NEWEST]) {
      expect(locations(xml)).toContain(`${APP_ORIGIN}/entries/${id}`);
    }
    expect(xml).toContain(
      `<loc>${APP_ORIGIN}/entries/${ENTRY_NEWEST}</loc><lastmod>2026-09-11</lastmod>`,
    );
    // A page is a range and nothing else: the static pages are on the other
    // document, so nothing is listed twice.
    expect(xml).not.toContain(`${APP_ORIGIN}/policy`);
  }, 60_000);

  it("answers an empty range with an empty document, not a refusal", async () => {
    const response = await get(
      `${APP_ORIGIN}/sitemap-entries-3.xml`,
      production(),
    );
    // A page whose range nothing has been submitted in yet is a page that will
    // fill: a 404 would tell a crawler the address was wrong rather than empty.
    expect(response.status).toBe(200);
    expect(locations(await response.text())).toEqual([]);
  }, 60_000);

  it("splits the pages at the bound, half-open, and lists nothing twice", async () => {
    // The boundary itself: a range that included its own end would put the
    // entry at position SITEMAP_MAX_ENTRIES on page one *and* page two, and a
    // crawler would be handed one entry at two addresses.
    const pages = await Promise.all(
      [1, 2].map(async (page) =>
        locations(
          await (
            await get(`${APP_ORIGIN}/sitemap-entries-${page}.xml`, production())
          ).text(),
        ),
      ),
    );
    const on = (id: string) =>
      pages
        .map((found, index) =>
          found.includes(`${APP_ORIGIN}/entries/${id}`) ? index + 1 : 0,
        )
        .filter((page) => page !== 0);

    expect(on(ENTRY_BEFORE_BOUNDARY)).toEqual([1]);
    expect(on(ENTRY_ON_BOUNDARY)).toEqual([2]);
    expect(on(ENTRY_AFTER_BOUNDARY)).toEqual([2]);
  }, 60_000);

  it("answers a HEAD, and refuses every other method", async () => {
    for (const path of ["/sitemap-pages.xml", "/sitemap-entries-1.xml"]) {
      const head = await get(`${APP_ORIGIN}${path}`, production(), {
        method: "HEAD",
      });
      expect([path, head.status]).toEqual([path, 200]);
      expect(head.body).toBeNull();

      const put = await get(`${APP_ORIGIN}${path}`, production(), {
        method: "PUT",
      });
      expect([path, put.status]).toEqual([path, 405]);
      expect(put.headers.get("allow")).toContain("GET");
    }
  }, 60_000);

  it("is held at the edge like the sitemap that names it", () => {
    for (const path of ["/sitemap-pages.xml", "/sitemap-entries-1.xml"]) {
      expect([path, cacheablePath(path)]).toEqual([path, true]);
    }
  });

  it("is not offered on the apex, which has one page", async () => {
    const response = await get(`${APEX_ORIGIN}/sitemap-pages.xml`, production());
    expect(response.status).toBe(404);
    // And the apex's own sitemap is the one line it has always been.
    const xml = await (
      await get(`${APEX_ORIGIN}/sitemap.xml`, production())
    ).text();
    expect(locations(xml)).toEqual([`${APEX_ORIGIN}/`]);
    expect(xml).not.toContain("<sitemapindex");
  }, 60_000);
});

// ---------------------------------------------------------------------------
// The icon
// ---------------------------------------------------------------------------

describe("the favicon", () => {
  for (const path of ["/favicon.svg", "/favicon.ico"]) {
    it(`answers ${path} with the same drawn bytes`, async () => {
      const response = await get(`${APP_ORIGIN}${path}`, envWith());
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("image/svg+xml");
      // The stylesheets' own hour: one file, the same for every reader.
      expect(response.headers.get("cache-control")).toBe("public, max-age=3600");
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");

      const svg = await response.text();
      expect(svg.startsWith("<svg")).toBe(true);
      expect(svg).toContain(`viewBox="0 0 64 64"`);
      expect(svg).toContain(FAVICON_BACKGROUND);
      expect(svg).toContain(FAVICON_ACCENT);
      // Nothing is fetched to draw it: no font, no image, no stylesheet. The
      // one URL in the file is the SVG namespace, which is a name and not an
      // address — nothing is ever fetched from it.
      expect(svg.replace(`xmlns="http://www.w3.org/2000/svg"`, "")).not.toContain(
        "http",
      );
      expect(svg).not.toMatch(/href|src=|url\(|@import/);
      // And no glyph: a `<text>` is whatever font the viewer happens to have.
      expect(svg).not.toContain("<text");
      expect(new TextEncoder().encode(svg).length).toBeLessThan(600);
    }, 60_000);
  }

  it("uses the app's own palette, as src/ui/styles.ts holds it", async () => {
    const sheet = await (
      await get(`${APP_ORIGIN}/static/app.css`, envWith())
    ).text();
    expect(sheet).toContain(`--bg: ${FAVICON_BACKGROUND}`);
    expect(sheet).toContain(`--accent: ${FAVICON_ACCENT}`);
  }, 60_000);

  it("answers a HEAD with the same headers and no body", async () => {
    const head = await get(`${APP_ORIGIN}/favicon.svg`, envWith(), {
      method: "HEAD",
    });
    expect(head.status).toBe(200);
    expect(head.body).toBeNull();
    expect(head.headers.get("content-type")).toBe("image/svg+xml");
  }, 60_000);
});

// ---------------------------------------------------------------------------
// What every page carries
// ---------------------------------------------------------------------------

describe("the Link header", () => {
  it("preloads the app stylesheet and opens the font connection", async () => {
    for (const path of ["/domains", "/policy", "/api"]) {
      const response = await get(`${APP_ORIGIN}${path}`, envWith({ APP_HOST }), {
        headers: HTML,
      });
      expect([path, response.status]).toEqual([path, 200]);
      expect([path, response.headers.get("link")]).toEqual([
        path,
        expectedLink(APP_CSS_HREF),
      ]);
    }
  }, 60_000);

  it("preloads the landing page's own stylesheet instead", async () => {
    const response = await get(`${APP_ORIGIN}/landing`, envWith(), {
      headers: HTML,
    });
    expect(response.headers.get("link")).toBe(expectedLink(LANDING_CSS_HREF));

    // And at the apex's root, which is the same page reached the way a reader
    // reaches it.
    const apex = await get(
      `${APEX_ORIGIN}/`,
      envWith({ ENVIRONMENT: "production", APEX_HOST, APP_HOST }),
      { headers: HTML },
    );
    expect(apex.headers.get("link")).toBe(expectedLink(LANDING_CSS_HREF));
  }, 60_000);

  it("is carried by an error page too, and never by a file", async () => {
    const missing = await get(
      `${APP_ORIGIN}/entries/nmk_nonsense`,
      envWith({ APP_HOST }),
      { headers: HTML },
    );
    expect(missing.status).toBe(404);
    expect(missing.headers.get("link")).toBe(expectedLink(APP_CSS_HREF));

    for (const path of [
      "/robots.txt",
      "/sitemap.xml",
      "/sitemap-pages.xml",
      "/favicon.svg",
    ]) {
      const file = await get(`${APP_ORIGIN}${path}`, envWith({ APP_HOST }));
      expect([path, file.headers.get("link")]).toEqual([path, null]);
    }
  }, 60_000);

  it("is carried by the final not-found too, which is a page like any other", async () => {
    // The 404 no door answered (src/worker/index.ts): it is the app's layout
    // linking the app's stylesheet, so it must ask for that sheet as early as
    // every other page does.
    const missing = await get(`${APP_ORIGIN}/nothing-here`, envWith({ APP_HOST }), {
      headers: HTML,
    });
    expect(missing.status).toBe(404);
    expect(missing.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(missing.headers.get("link")).toBe(expectedLink(APP_CSS_HREF));

    // The agent's twin is a record and carries no hint about a stylesheet.
    const json = await get(`${APP_ORIGIN}/nothing-here`, envWith({ APP_HOST }));
    expect(json.status).toBe(404);
    expect(json.headers.get("link")).toBeNull();
  }, 60_000);
});

describe("the canonical origin a page names", () => {
  it("is the configured app host, wherever the page was reached", async () => {
    const page = await (
      await get(`${PREVIEW_ORIGIN}/domains`, envWith({ APP_HOST }), {
        headers: HTML,
      })
    ).text();
    expect(page).toContain(`rel="canonical"`);
    expect(page).toContain(`href="${APP_ORIGIN}/domains"`);
  }, 60_000);

  it("is the request's own origin when none is configured", async () => {
    const page = await (
      await get(`${PREVIEW_ORIGIN}/domains`, envWith(), { headers: HTML })
    ).text();
    expect(page).toContain(`href="${PREVIEW_ORIGIN}/domains"`);
  }, 60_000);

  it("is the apex itself for the landing served at its root", async () => {
    const env = envWith({ ENVIRONMENT: "production", APEX_HOST, APP_HOST });
    const landing = await (
      await get(`${APEX_ORIGIN}/`, env, { headers: HTML })
    ).text();
    expect(landing).toContain(`href="${APEX_ORIGIN}/"`);

    // Every other path on the apex is the app's page reached at the wrong host,
    // and says so: two hosts serving one document is what a canonical is for.
    const page = await (
      await get(`${APEX_ORIGIN}/domains`, env, { headers: HTML })
    ).text();
    expect(page).toContain(`href="${APP_ORIGIN}/domains"`);
  }, 60_000);
});

describe("the edge cache", () => {
  it("holds all four files beside the pages", () => {
    for (const path of [
      "/robots.txt",
      "/sitemap.xml",
      "/favicon.svg",
      "/favicon.ico",
    ]) {
      expect([path, cacheablePath(path)]).toEqual([path, true]);
    }
  });
});

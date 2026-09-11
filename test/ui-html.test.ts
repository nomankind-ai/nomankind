/**
 * The escaping and the document shell.
 *
 * The browsing UI renders somebody else's text — a claim, a subject, a citation,
 * a rejection reason — into a page that carries no script and is served under a
 * content-security-policy that forbids one. Both halves of that have to be true
 * or neither is worth anything, so these tests hold the escaping to the five
 * characters and the response to the exact policy string.
 */

import { describe, expect, it } from "vitest";
import {
  APEX_URL,
  APP_CSS_HREF,
  CONTACT_EMAIL,
  CONTENT_SECURITY_POLICY,
  badge,
  cssResponse,
  escapeHtml,
  fmtDate,
  fmtInstant,
  html,
  htmlResponse,
  layout,
  link,
  raw,
  safeHref,
  shortHash,
  statusClass,
} from "../src/ui/html.js";
import { APP_CSS } from "../src/ui/styles.js";
import type { PageContext } from "../src/ui/types.js";

const ctx: PageContext = {
  environment: "demo",
  path: "/entries",
  origin: "https://demo.nomankind.ai",
};

describe("escapeHtml", () => {
  it("escapes the five characters that can end markup", () => {
    expect(escapeHtml(`&<>"'`)).toBe("&amp;&lt;&gt;&quot;&#39;");
  });

  it("escapes the ampersand first, so escapes cannot escape each other", () => {
    expect(escapeHtml("&lt;")).toBe("&amp;lt;");
  });

  it("renders null and undefined as nothing, and numbers and booleans as text", () => {
    expect(escapeHtml(null)).toBe("");
    expect(escapeHtml(undefined)).toBe("");
    expect(escapeHtml(0)).toBe("0");
    expect(escapeHtml(false)).toBe("false");
    expect(escapeHtml(48213)).toBe("48213");
  });
});

describe("the html template", () => {
  it("never lets a script tag survive an interpolation", () => {
    const hostile = `<script>fetch("/steal")</script>`;
    const out = html`<p>${hostile}</p>`;
    expect(out.markup).not.toContain("<script");
    expect(out.markup).toBe(
      `<p>&lt;script&gt;fetch(&quot;/steal&quot;)&lt;/script&gt;</p>`,
    );
  });

  it("cannot be broken out of an attribute", () => {
    const hostile = `" onmouseover="alert(1)`;
    const out = html`<span title="${hostile}"></span>`;
    expect(out.markup).not.toContain(`onmouseover="`);
  });

  it("passes raw markup through untouched", () => {
    expect(html`<div>${raw("<b>ok</b>")}</div>`.markup).toBe(
      "<div><b>ok</b></div>",
    );
  });

  it("joins an array of Safe values without a separator", () => {
    const rows = ["a", "b", "c"].map((value) => html`<li>${value}</li>`);
    expect(html`<ul>${rows}</ul>`.markup).toBe(
      "<ul><li>a</li><li>b</li><li>c</li></ul>",
    );
  });

  it("escapes a plain string inside an interpolated array", () => {
    expect(html`${["<b>", raw("<i>")]}`.markup).toBe("&lt;b&gt;<i>");
  });
});

describe("safeHref", () => {
  it("accepts http and https", () => {
    expect(safeHref("https://openai.com/pricing")).toBe(
      "https://openai.com/pricing",
    );
    expect(safeHref("http://example.test/a?b=c")).toBe("http://example.test/a?b=c");
  });

  it("refuses everything else", () => {
    for (const url of [
      "javascript:alert(1)",
      "JavaScript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "/entries",
      "entries",
      "",
      null,
      undefined,
      42,
    ]) {
      expect(safeHref(url)).toBeNull();
    }
  });

  it("renders the label as plain text when the href is refused", () => {
    expect(link("javascript:alert(1)", "Source").markup).toBe("Source");
  });

  it("gives an external link target and rel", () => {
    const out = link("https://example.test/", "Paper", true).markup;
    expect(out).toContain(`target="_blank"`);
    expect(out).toContain(`rel="noopener noreferrer nofollow"`);
  });
});

describe("formatting", () => {
  it("shortens a hash and drops the algorithm prefix", () => {
    expect(shortHash(`sha256:${"a".repeat(64)}`)).toBe(`${"a".repeat(12)}…`);
    expect(shortHash("abc")).toBe("abc");
  });

  it("shows an instant as a date, a time and a Z", () => {
    expect(fmtInstant("2026-09-09T04:49:44Z")).toBe("2026-09-09 04:49:44Z");
    expect(fmtInstant("2026-09-09T04:49:44.512Z")).toBe("2026-09-09 04:49:44Z");
    expect(fmtInstant(null)).toBe("—");
  });

  it("shows a date, from either a date or an instant", () => {
    expect(fmtDate("2026-09-09")).toBe("2026-09-09");
    expect(fmtDate("2026-09-09T04:49:44Z")).toBe("2026-09-09");
    expect(fmtDate(null)).toBe("—");
  });

  it("maps every status to its own class, and an unknown one to the neutral class", () => {
    expect(statusClass("verified")).toBe("s-verified");
    expect(statusClass("superseded")).toBe("s-superseded");
    expect(statusClass("draft")).toBe("s-draft");
    expect(statusClass("rejected")).toBe("s-rejected");
    expect(statusClass("overturned")).toBe("s-overturned");
    expect(statusClass("something-else")).toBe("s-other");
  });

  it("builds a badge with its kind as a class", () => {
    expect(badge("s-verified", "verified").markup).toBe(
      `<span class="badge s-verified">verified</span>`,
    );
  });
});

describe("layout", () => {
  const document = layout(ctx, {
    title: "Entries",
    body: html`<p>body</p>`,
    description: "The log.",
  });

  it("names the page and then nomankind", () => {
    expect(document).toContain("<title>Entries · nomankind</title>");
  });

  it("carries the environment badge", () => {
    expect(document).toContain(`<span class="env mono">demo</span>`);
  });

  it("marks the nav item whose href is a prefix of the path", () => {
    expect(document).toContain(`<a class="nav nav-active" href="/entries">Entries</a>`);
    expect(document).toContain(`<a class="nav" href="/domains">Domains</a>`);
  });

  /**
   * D-104: the nav is five items, and Docs stands for the six documentation
   * pages that used to each have one of their own. A reader who opens the
   * policy tables is still somewhere the nav can show them.
   */
  it("carries five items and marks Docs active on every documentation path", () => {
    const nav = document.slice(
      document.indexOf(`<nav class="nav-list">`),
      document.indexOf("</nav>"),
    );
    const labels = [...nav.matchAll(/<a class="nav[^"]*" href="([^"]+)">([^<]+)</g)].map(
      (each) => [each[1], each[2]],
    );
    expect(labels).toEqual([
      ["/entries", "Entries"],
      ["/domains", "Domains"],
      ["/operators", "Operators"],
      ["/docs", "Docs"],
      ["/status", "Status"],
    ]);
    for (const path of [
      "/docs",
      "/docs/whitepaper",
      "/how-it-works",
      "/api",
      "/policy",
      "/genesis",
      "/dry-run",
    ]) {
      const page = layout({ ...ctx, path }, { title: "Docs", body: html`` });
      expect(page).toContain(`<a class="nav nav-active" href="/docs">Docs</a>`);
    }
    // And nowhere else: a log page is not a documentation page.
    const entries = layout(
      { ...ctx, path: "/entries" },
      { title: "Entries", body: html`` },
    );
    expect(entries).toContain(`<a class="nav" href="/docs">Docs</a>`);
  });

  it("marks the section active from a page below it", () => {
    const deep = layout(
      { ...ctx, path: "/entries/nmk_01J8Z00SEED1" },
      { title: "Entry", body: html`<p>body</p>` },
    );
    expect(deep).toContain(`<a class="nav nav-active" href="/entries">Entries</a>`);
  });

  it("links its own stylesheet and the font stylesheet", () => {
    expect(document).toContain(`<link rel="stylesheet" href="${APP_CSS_HREF}" />`);
    expect(APP_CSS_HREF).toMatch(/^\/static\/app\.css\?v=[0-9a-f]{8}$/);
    expect(document).toContain("https://fonts.googleapis.com/css2?family=Space+Grotesk");
    expect(document).toContain("family=JetBrains+Mono");
  });

  /**
   * The wordmark is the way back to the front door, and the front door is the
   * apex: a header on demo, on app or on a path of the apex itself that pointed
   * at "/" sent a reader to that host's own root instead. One fixed URL, the
   * same from every environment, and no rel and no target — it is our host.
   */
  it("points the wordmark at the apex from every environment", () => {
    expect(APEX_URL).toBe("https://nomankind.ai/");
    for (const environment of ["local", "demo", "production"]) {
      const page = layout(
        { ...ctx, environment },
        { title: "Entries", body: html`<p>body</p>` },
      );
      expect(page).toContain(`<a class="wordmark" href="${APEX_URL}">`);
      expect(page).not.toContain(`<a class="wordmark" href="/">`);
      const anchor = page.slice(
        page.indexOf(`<a class="wordmark"`),
        page.indexOf("</a>", page.indexOf(`<a class="wordmark"`)),
      );
      expect(anchor).not.toContain("rel=");
      expect(anchor).not.toContain("target=");
    }
  });

  it("carries no script and no inline style attribute", () => {
    expect(document).not.toContain("<script");
    expect(document).not.toContain(" style=");
    expect(document).not.toContain(" onclick=");
  });

  it("links the repository, the mirror, the paper and a way to write in the footer", () => {
    expect(document).toContain("https://github.com/nomankind-ai/nomankind");
    // D-104: the paper is a page of this site now, served from the
    // repository's own bytes, so the footer links it relatively — no new tab
    // and no nofollow, which are for somebody else's URL.
    expect(document).toContain(`<a href="/docs/whitepaper">Whitepaper</a>`);
    expect(document).not.toContain(
      "https://github.com/nomankind-ai/nomankind/blob/main/paper/WHITEPAPER.md",
    );
    expect(document).toContain("Apache-2.0");
    // The daily CC0 export (Section 11), between the two repositories a reader
    // can leave with. Ours and internal, so it is a plain link: no new tab and
    // no nofollow, which are for somebody else's URL.
    expect(document).toContain(`<a href="/mirror/latest">Mirror</a>`);
    const footer = document.slice(document.indexOf("<footer"));
    expect(footer.indexOf("Repository")).toBeLessThan(footer.indexOf(">Mirror<"));
    expect(footer.indexOf(">Mirror<")).toBeLessThan(footer.indexOf("Whitepaper"));
    // D-085: a free way to reach a person, on every app page of every
    // environment. A mailto is neither http nor somebody else's URL, so it is a
    // plain anchor: no new tab, and no rel to protect a referrer nobody sends.
    expect(CONTACT_EMAIL).toBe("hello@nomankind.ai");
    expect(footer).toContain(`<a href="mailto:${CONTACT_EMAIL}">Contact</a>`);
    expect(footer.indexOf("Whitepaper")).toBeLessThan(footer.indexOf(">Contact<"));
    const contact = footer.slice(
      footer.indexOf(`<a href="mailto:`),
      footer.indexOf("</a>", footer.indexOf(`<a href="mailto:`)),
    );
    expect(contact).not.toContain("rel=");
    expect(contact).not.toContain("target=");
  });

  it("starts with a doctype and declares the language", () => {
    expect(document.startsWith("<!doctype html>")).toBe(true);
    expect(document).toContain(`<html lang="en">`);
  });

  it("escapes the title and the description it is given", () => {
    const hostile = layout(ctx, {
      title: `</title><script>x</script>`,
      body: html`<p>body</p>`,
      description: `" onload="x`,
    });
    expect(hostile).not.toContain("<script");
    expect(hostile).not.toContain(`onload="`);
  });
});

describe("htmlResponse", () => {
  const response = htmlResponse("<!doctype html><html></html>");

  it("serves HTML that nothing may cache", () => {
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("vary")).toBe("Accept");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("carries exactly the policy that forbids script", () => {
    expect(response.headers.get("content-security-policy")).toBe(
      "default-src 'none'; style-src 'self' https://fonts.googleapis.com; " +
        "font-src https://fonts.gstatic.com; img-src 'self' data:; " +
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    expect(CONTENT_SECURITY_POLICY).not.toContain("script-src");
  });

  it("takes a status and extra headers", () => {
    const notFound = htmlResponse("<!doctype html>", 404, { "x-note": "gone" });
    expect(notFound.status).toBe(404);
    expect(notFound.headers.get("x-note")).toBe("gone");
    expect(notFound.headers.get("content-security-policy")).toBe(
      CONTENT_SECURITY_POLICY,
    );
  });
});

describe("cssResponse", () => {
  it("serves cacheable CSS", () => {
    const response = cssResponse("body{}");
    expect(response.headers.get("content-type")).toBe("text/css; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("public, max-age=3600");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });
});

describe("APP_CSS", () => {
  /** Every class the pages write that the stylesheet has to answer for. */
  const selectors = [
    // The app tables and the documentation tables are one rule set.
    "table.dense,\ntable.table {",
    "table.dense th,\ntable.table th {",
    "table.dense td,\ntable.table td {",
    // The documentation panels: the header row and the definition list.
    ".panel-title {",
    "dl.kv,\ndl.dl {",
    // The scroll container, and the floor that makes it do something.
    ".table-wrap { overflow-x: auto; }",
    "min-width: 640px;",
    // An identifier in a table is one token and never breaks per character.
    "table.dense td.break,\ntable.table td.break {",
  ];

  it("defines every class the pages write", () => {
    for (const selector of selectors) {
      expect(APP_CSS, `${selector} is not in the stylesheet`).toContain(
        selector,
      );
    }
  });

  it("styles no landing class: the landing owns its own stylesheet", () => {
    // D-021. The landing's rules live in src/ui/pages/landing.ts, and a dead
    // `.landing {}` here shadowed the real export by name.
    expect(APP_CSS).not.toContain(".landing");
  });
});

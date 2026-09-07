import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  BLOCK_ELEMENTS,
  REMOVED_ELEMENTS,
  extractHtml,
} from "../src/extract.js";
import { normalizeText } from "../src/normalize.js";

/**
 * The extractor of snapshot normalization norm-v1.2, rule by rule. Each rule of
 * the published set is pinned on its own, so a change to the norm document has
 * to change a test here and cannot pass unnoticed.
 */

const FIXTURES = [
  "pricing-base.html",
  "model-card-base.html",
  "rate-limits.html",
  "changelog-articles.html",
  "plain-page.html",
  "fragment-no-body.html",
  "nested-asides.html",
  "script-tricks.html",
  "attr-gt.html",
  "uppercase-unclosed.html",
] as const;

function fixture(name: string): string {
  return readFileSync(new URL(`./fixtures/html/${name}`, import.meta.url), {
    encoding: "utf8",
  });
}

describe("the norm-v1.2 rule set it publishes", () => {
  it("names the removed elements the norm document lists", () => {
    expect([...REMOVED_ELEMENTS]).toEqual([
      "head",
      "script",
      "style",
      "template",
      "noscript",
      "nav",
      "header",
      "footer",
      "aside",
      "svg",
    ]);
  });

  it("names the block elements the norm document lists", () => {
    expect(BLOCK_ELEMENTS).toHaveLength(36);
    expect([...BLOCK_ELEMENTS]).toEqual([...BLOCK_ELEMENTS].sort());
    for (const name of ["div", "p", "li", "table", "tr", "main", "h1", "hr"]) {
      expect(BLOCK_ELEMENTS).toContain(name);
    }
    expect(BLOCK_ELEMENTS).not.toContain("br");
    expect(BLOCK_ELEMENTS).not.toContain("td");
    expect(BLOCK_ELEMENTS).not.toContain("th");
  });

  it("freezes both lists so no caller can edit the rule in place", () => {
    expect(Object.isFrozen(REMOVED_ELEMENTS)).toBe(true);
    expect(Object.isFrozen(BLOCK_ELEMENTS)).toBe(true);
  });
});

describe("E2, tokenizing", () => {
  it("drops a comment and its content", () => {
    expect(extractHtml("<p>a<!-- hidden -->b</p>")).toBe("\nab\n");
  });

  it("drops an unterminated comment through the end of the document", () => {
    expect(extractHtml("<p>a<!-- hidden b</p>")).toBe("\na");
  });

  it("drops a doctype, a declaration and a processing instruction", () => {
    expect(extractHtml("<!DOCTYPE html><p>a</p><?php echo 1; ?>b")).toBe(
      "\na\nb",
    );
  });

  it("keeps a bare < that starts no tag as text", () => {
    expect(extractHtml("<p>a < b and 3<4</p>")).toBe("\na < b and 3<4\n");
  });

  it("drops an unterminated tag and everything after it", () => {
    expect(extractHtml("<p>a</p><p>b")).toBe("\na\n\nb");
    expect(extractHtml("<p>a</p><div class='x'")).toBe("\na\n");
  });

  it("lowercases tag names, so uppercase markup extracts the same", () => {
    expect(extractHtml("<P>a</P>")).toBe(extractHtml("<p>a</p>"));
  });
});

describe("E3, removing elements with their content", () => {
  it("drops a script whose text contains what looks like a tag", () => {
    expect(
      extractHtml('<div>keep<script>var s = "</div>";</script>tail</div>'),
    ).toBe("\nkeeptail\n");
  });

  it("drops a comment inside a script with the script", () => {
    const html = fixture("script-tricks.html");
    const text = normalizeText(extractHtml(html));
    expect(text).toContain("The widget renders a price table.");
    expect(text).not.toContain("markup");
    expect(text).not.toContain("a comment inside a script");
    expect(text).not.toContain("an ordinary comment");
  });

  it("counts nesting for an aside, so the outer end tag closes both", () => {
    expect(
      extractHtml(
        "<main><p>a</p><aside>x<aside>y</aside>z</aside><p>b</p></main>",
      ),
    ).toBe("\na\n\nb\n");
  });

  it("runs an unclosed removed element to the end of the document", () => {
    expect(extractHtml("<p>a</p><footer>b<p>c</p>")).toBe("\na\n");
  });

  it("drops only itself when a removed element is self-closing", () => {
    expect(extractHtml("<p>a</p><svg /><p>b</p>")).toBe("\na\n\nb\n");
  });

  it("removes before scoping, so a nav inside main goes too", () => {
    expect(extractHtml("<main><nav>skip</nav>keep</main>")).toBe("keep");
  });

  it("keeps the header and footer out of the nested-aside guide", () => {
    const text = normalizeText(extractHtml(fixture("nested-asides.html")));
    expect(text).toContain("Retry on 429 and on 5xx, with full jitter.");
    expect(text).not.toContain("Do not retry a 400");
    expect(text).not.toContain("Inner aside text");
    expect(text).not.toContain("Edited by the docs team");
    expect(text).not.toContain("Guides");
  });
});

describe("E4, scoping", () => {
  it("prefers main over article and body", () => {
    expect(
      extractHtml("<body><article>art</article><main>main text</main></body>"),
    ).toBe("main text");
  });

  it("joins every outermost article with a single newline", () => {
    expect(
      extractHtml(
        "<article>one<article>nested</article></article><article>two</article>",
      ),
    ).toBe("one\nnested\n\ntwo");
  });

  it("collects an article only once when it nests inside another", () => {
    const text = normalizeText(
      extractHtml(fixture("changelog-articles.html")),
    );
    expect(text).toContain("Batch endpoint");
    expect(text).toContain("Streaming fixes");
    expect(text).toContain("Deprecation");
    expect(text).not.toContain("Subscribe to the feed");
  });

  it("falls back to the body when there is no main or article", () => {
    expect(
      extractHtml("<html><head><title>t</title></head><body><p>hi</p></body>"),
    ).toBe("\nhi\n");
    const text = normalizeText(extractHtml(fixture("plain-page.html")));
    expect(text).toContain("About Northwind");
    expect(text).not.toContain("About us");
  });

  it("falls back to the whole document when there is no body", () => {
    expect(extractHtml("<p>alpha</p>")).toBe("\nalpha\n");
    const text = normalizeText(extractHtml(fixture("fragment-no-body.html")));
    expect(text).toContain("Support hours");
    expect(text).toContain("Escalation");
  });

  it("runs an unclosed main to the end of the document", () => {
    expect(extractHtml("<body><main>tail<p>more</p></body>")).toBe(
      "tail\nmore\n",
    );
  });
});

describe("E5, tags to text", () => {
  it("turns br into a newline, as a start tag or self-closing", () => {
    expect(extractHtml("<div>a<br>b<br/>c</div>")).toBe("\na\nb\nc\n");
  });

  it("turns a stray br end tag into nothing", () => {
    expect(extractHtml("a</br>b")).toBe("ab");
  });

  it("turns each block tag, start and end, into a newline", () => {
    expect(extractHtml("<div>a</div><p>b</p>")).toBe("\na\n\nb\n");
  });

  it("turns td and th tags into a single space", () => {
    expect(
      extractHtml("<table><tr><td>x</td><td>y</td></tr></table>"),
    ).toBe("\n\n x  y \n\n");
    expect(normalizeText(extractHtml("<tr><th>H</th><td>1</td></tr>"))).toBe(
      "H 1",
    );
  });

  it("turns every other tag, known or unknown, into nothing", () => {
    expect(extractHtml("<p>a<mystery data-x='1'>b</mystery><em>c</em></p>")).toBe(
      "\nabc\n",
    );
    expect(extractHtml("<p>a<img src='x.png'/>b</p>")).toBe("\nab\n");
  });

  it("never emits an attribute, even one holding a > in quotes", () => {
    expect(extractHtml(`<p title="a > b">text</p>`)).toBe("\ntext\n");
    expect(extractHtml(`<div data-x='c > d'>y</div>`)).toBe("\ny\n");
    const text = normalizeText(extractHtml(fixture("attr-gt.html")));
    expect(text).toContain("Text after the tricky attributes.");
    expect(text).not.toContain("main > section");
    expect(text).not.toContain("carefully");
  });
});

describe("E6, character references", () => {
  it("decodes the named references in the table", () => {
    expect(extractHtml("<p>&amp;&lt;&gt;&quot;&apos;</p>")).toBe(
      "\n&<>\"'\n",
    );
  });

  it("decodes &nbsp; to a plain space", () => {
    expect(extractHtml("<p>a&nbsp;b</p>")).toBe("\na b\n");
  });

  it("decodes decimal and hexadecimal references", () => {
    expect(extractHtml("&#65;&#x42;&#X43;")).toBe("ABC");
    expect(extractHtml("&#8212;")).toBe("\u2014");
  });

  it("turns U+00A0 into a space however it arrives", () => {
    expect(extractHtml("a&#160;b")).toBe("a b");
    expect(extractHtml("a&#xA0;b")).toBe("a b");
    expect(extractHtml("a b")).toBe("a b");
  });

  it("replaces zero, surrogates and out-of-range code points", () => {
    expect(extractHtml("&#0;")).toBe("\uFFFD");
    expect(extractHtml("&#xD800;")).toBe("\uFFFD");
    expect(extractHtml("&#xDFFF;")).toBe("\uFFFD");
    expect(extractHtml("&#x110000;")).toBe("\uFFFD");
  });

  it("keeps an unknown or unterminated reference literal", () => {
    expect(extractHtml("&copy; &amp &#65 &#; &")).toBe("&copy; &amp &#65 &#; &");
  });

  it("decodes in a single pass, so &amp;lt; yields &lt;", () => {
    expect(extractHtml("&amp;lt;")).toBe("&lt;");
    expect(extractHtml("&amp;amp;")).toBe("&amp;");
  });

  it("decodes the entities in the rate-limit table", () => {
    const text = normalizeText(extractHtml(fixture("rate-limits.html")));
    expect(text).toContain("Requests / min");
    expect(text).toContain("per organization & per model");
    expect(text).toContain("60 second window");
    expect(text).toContain("support@example.com");
    expect(text).toContain("&mdash;");
  });
});

describe("determinism", () => {
  it("extracts and normalizes each fixture page identically ten times", () => {
    expect(FIXTURES).toHaveLength(10);
    for (const name of FIXTURES) {
      const html = fixture(name);
      const first = normalizeText(extractHtml(html));
      expect(first.length).toBeGreaterThan(0);
      for (let run = 0; run < 10; run += 1) {
        expect(normalizeText(extractHtml(html))).toBe(first);
      }
    }
  });

  it("leaves its input untouched, being a pure function", () => {
    const html = fixture("pricing-base.html");
    const copy = `${html}`;
    extractHtml(html);
    expect(html).toBe(copy);
  });
});

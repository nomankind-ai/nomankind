/**
 * The markdown renderer the three served documents are drawn with (D-104).
 *
 * Two things are on trial here. The renderer has to understand the markdown the
 * repository's documents are actually written in — headings, lists one level
 * deep, fenced code, pipe tables, links, emphasis, a blockquote — and it has to
 * be safe to point at a document nobody reviewed: every text run escaped, raw
 * HTML in the source escaped rather than emitted, and a `javascript:` target
 * never an anchor, because escaping is no defence in a href.
 *
 * The last block runs the three real documents through it. They are the record
 * of what this thing claims to be, so the test is not a snapshot: it checks
 * that nothing the content-security-policy forbids comes out, and that no angle
 * bracket from the source survives as markup.
 */

import { describe, expect, it } from "vitest";

import {
  FORK_MARKDOWN,
  FORK_SOURCE_PATH,
  SUMMARY_MARKDOWN,
  SUMMARY_SOURCE_PATH,
  WHITEPAPER_MARKDOWN,
  WHITEPAPER_SOURCE_PATH,
} from "../src/ui/docs.generated.js";
import { headings, renderMarkdown, sections } from "../src/ui/markdown.js";

/** Every construct the renderer covers, in one document. */
const FIXTURE = [
  "# The title",
  "",
  "A paragraph with **strong**, *emphasis*, `inline code` and a",
  "hard line break in the middle of it.",
  "",
  "## A section",
  "",
  "- a bullet with [a link](https://example.org/thing)",
  "- another bullet, wrapped",
  "  onto a second line",
  "",
  "1. a numbered item",
  "2. a second one, with a nested list",
  "   - nested first",
  "   - nested second",
  "",
  "```sh",
  "npm run gen:docs",
  "```",
  "",
  "### A deeper heading",
  "",
  "> A quoted line.",
  "",
  "| Path | What it holds |",
  "| --- | --- |",
  "| `mirror.json` | The manifest. |",
  "| `seals.jsonl` | Every seal. |",
  "",
  "---",
  "",
  "#### The deepest heading",
  "",
  "## A section",
  "",
  "The end.",
].join("\n");

const rendered = renderMarkdown(FIXTURE).markup;

describe("renderMarkdown", () => {
  it("renders headings one to four with slug ids", () => {
    expect(rendered).toContain(`<h1 id="the-title">The title</h1>`);
    expect(rendered).toContain(`<h2 id="a-section">A section</h2>`);
    expect(rendered).toContain(`<h3 id="a-deeper-heading">A deeper heading</h3>`);
    expect(rendered).toContain(`<h4 id="the-deepest-heading">The deepest heading</h4>`);
  });

  it("deduplicates a repeated heading with a numeric suffix", () => {
    expect(rendered).toContain(`<h2 id="a-section-2">A section</h2>`);
    expect(rendered.match(/id="a-section"/g)).toHaveLength(1);
  });

  it("collapses a hard line break inside a paragraph to a space", () => {
    expect(rendered).toContain(
      `<p class="prose">A paragraph with <strong>strong</strong>, <em>emphasis</em>, ` +
        `<code>inline code</code> and a hard line break in the middle of it.</p>`,
    );
  });

  it("renders a bullet list, a numbered list and one level of nesting", () => {
    expect(rendered).toContain(
      `<li>a bullet with <a href="https://example.org/thing" rel="noopener noreferrer nofollow">a link</a></li>`,
    );
    expect(rendered).toContain(`<li>another bullet, wrapped onto a second line</li>`);
    expect(rendered).toContain(
      `<ol><li>a numbered item</li><li>a second one, with a nested list` +
        `<ul><li>nested first</li><li>nested second</li></ul></li></ol>`,
    );
  });

  it("renders a fenced block as pre.block and ignores its language", () => {
    expect(rendered).toContain(`<pre class="block">npm run gen:docs</pre>`);
    expect(rendered).not.toContain("sh<");
  });

  it("renders a blockquote and a horizontal rule", () => {
    expect(rendered).toContain(
      `<blockquote class="note"><p class="prose">A quoted line.</p></blockquote>`,
    );
    expect(rendered).toContain("<hr />");
  });

  it("renders a pipe table as table.table inside a scroller", () => {
    expect(rendered).toContain(`<div class="table-wrap"><table class="table">`);
    expect(rendered).toContain(`<th>Path</th>`);
    expect(rendered).toContain(
      `<td class="prose"><code>mirror.json</code></td><td class="prose">The manifest.</td>`,
    );
    // The delimiter row is a rule of the table, not a row of it.
    expect(rendered).not.toContain("---</td>");
  });

  it("escapes raw HTML in the source rather than emitting it", () => {
    const hostile = renderMarkdown(
      "A paragraph with <script>alert(1)</script> and `<seal seq>` in it.",
    ).markup;
    expect(hostile).not.toContain("<script");
    expect(hostile).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(hostile).toContain("<code>&lt;seal seq&gt;</code>");
  });

  it("refuses to make an anchor of a target that is not http or https", () => {
    for (const target of ["javascript:alert(1)", "data:text/html,x", "mailto:a@b.c"]) {
      const out = renderMarkdown(`See [the label](${target}).`).markup;
      expect(out).toContain("the label");
      expect(out).not.toContain("<a ");
      expect(out).not.toContain("href=");
    }
  });

  it("makes an anchor of a bare URL in angle brackets, as the references write them", () => {
    expect(renderMarkdown("Protocol site: <https://1f916.org>.").markup).toContain(
      `<a href="https://1f916.org" rel="noopener noreferrer nofollow">https://1f916.org</a>`,
    );
    expect(
      renderMarkdown("See <http://example.org/a/b?c=d#e> for it.").markup,
    ).toContain(
      `<a href="http://example.org/a/b?c=d#e" rel="noopener noreferrer nofollow">` +
        `http://example.org/a/b?c=d#e</a>`,
    );
  });

  it("leaves everything else in angle brackets as escaped text", () => {
    for (const bracketed of [
      "<entry id>",
      "<seal seq, 8 digits>",
      "<javascript:alert(1)>",
      "<mailto:a@b.c>",
      "<b>",
    ]) {
      const out = renderMarkdown(`A line with ${bracketed} in it.`).markup;
      expect(out, `${bracketed} became markup`).not.toContain("<a ");
      expect(out, `${bracketed} became markup`).toContain("&lt;");
      expect(out).toContain("&gt;");
    }
  });

  it("keeps a fragment link as it is", () => {
    expect(renderMarkdown("[back](#the-title)").markup).toContain(
      `<a href="#the-title">back</a>`,
    );
  });

  it("maps a relative link to one of the three documents onto this site", () => {
    expect(renderMarkdown("[the paper](WHITEPAPER.md)", "paper").markup).toContain(
      `<a href="/docs/whitepaper">the paper</a>`,
    );
    expect(renderMarkdown("[one page](../paper/SUMMARY.md)", "docs").markup).toContain(
      `<a href="/docs/summary">one page</a>`,
    );
    expect(renderMarkdown("[the exit](docs/FORK.md#how-to-verify)").markup).toContain(
      `<a href="/docs/fork#how-to-verify">the exit</a>`,
    );
  });

  it("resolves every other relative link against the document's own directory", () => {
    expect(renderMarkdown("[the policy](../src/policy.ts)", "docs").markup).toContain(
      `<a href="https://github.com/nomankind-ai/nomankind/blob/main/src/policy.ts" ` +
        `rel="noopener noreferrer nofollow">the policy</a>`,
    );
    expect(renderMarkdown("[a sibling](NOTES.md)", "docs").markup).toContain(
      `<a href="https://github.com/nomankind-ai/nomankind/blob/main/docs/NOTES.md" ` +
        `rel="noopener noreferrer nofollow">a sibling</a>`,
    );
  });

  it("leaves an identifier's underscores alone", () => {
    expect(renderMarkdown("The prev_hash and the last_seq of it.").markup).toBe(
      `<p class="prose">The prev_hash and the last_seq of it.</p>`,
    );
    expect(renderMarkdown("A _quiet_ word.").markup).toContain("<em>quiet</em>");
  });
});

/** A document written the way the whitepaper is: sections at level one. */
const SECTIONED = [
  "# The paper",
  "",
  "An abstract.",
  "",
  "# Introduction",
  "",
  "## A subsection",
  "",
  "# Goals",
  "",
  "## Another subsection",
].join("\n");

describe("renderMarkdown under a page that prints the title", () => {
  const body = renderMarkdown(FIXTURE, "", { underTitle: "The title" }).markup;

  it("drops the document's own title where the page has already printed it", () => {
    expect(body).not.toContain("<h1");
    expect(body).not.toContain(">The title<");
  });

  it("renders every heading left one level down, with its id kept", () => {
    expect(body).toContain(`<h3 id="a-section">A section</h3>`);
    expect(body).toContain(`<h3 id="a-section-2">A section</h3>`);
    expect(body).toContain(`<h3 id="a-deeper-heading">A deeper heading</h3>`);
    // Three is as deep as this goes: an h4 one level down from an h2 is an h5,
    // and a document under a page title has no use for one.
    expect(body).toContain(`<h3 id="the-deepest-heading">The deepest heading</h3>`);
    expect(body).not.toContain("<h4");
  });

  it("keeps a title that is not the page's, one level down", () => {
    const kept = renderMarkdown(FIXTURE, "", { underTitle: "Something else" })
      .markup;
    expect(kept).not.toContain("<h1");
    expect(kept).toContain(`<h2 id="the-title">The title</h2>`);
  });

  it("renders a document whose sections are level one as level-two sections", () => {
    const sectioned = renderMarkdown(SECTIONED, "", {
      underTitle: "The paper",
    }).markup;
    expect(sectioned).not.toContain("<h1");
    expect(sectioned).toContain(`<h2 id="introduction">Introduction</h2>`);
    expect(sectioned).toContain(`<h2 id="goals">Goals</h2>`);
    expect(sectioned).toContain(`<h3 id="a-subsection">A subsection</h3>`);
  });

  it("leaves the document whole without the option", () => {
    expect(rendered).toContain(`<h1 id="the-title">The title</h1>`);
  });
});

describe("sections", () => {
  it("takes the level-1 headings after the title when there is more than one", () => {
    expect(sections(SECTIONED)).toEqual([
      { level: 1, text: "Introduction", id: "introduction" },
      { level: 1, text: "Goals", id: "goals" },
    ]);
  });

  it("takes the level-2 headings when the title is the only level-1 heading", () => {
    expect(sections(FIXTURE)).toEqual([
      { level: 2, text: "A section", id: "a-section" },
      { level: 2, text: "A section", id: "a-section-2" },
    ]);
  });
});

describe("headings", () => {
  it("returns the level-1 and level-2 headings with their ids, in order", () => {
    expect(headings(FIXTURE)).toEqual([
      { level: 1, text: "The title", id: "the-title" },
      { level: 2, text: "A section", id: "a-section" },
      { level: 2, text: "A section", id: "a-section-2" },
    ]);
  });

  it("ignores a heading-looking line inside a fenced block", () => {
    expect(headings(["```", "# not a heading", "```", "# a heading"].join("\n"))).toEqual([
      { level: 1, text: "a heading", id: "a-heading" },
    ]);
  });
});

describe("the three documents this Worker serves", () => {
  const documents = [
    { path: FORK_SOURCE_PATH, markdown: FORK_MARKDOWN },
    { path: WHITEPAPER_SOURCE_PATH, markdown: WHITEPAPER_MARKDOWN },
    { path: SUMMARY_SOURCE_PATH, markdown: SUMMARY_MARKDOWN },
  ];

  for (const document of documents) {
    const directory = document.path.slice(0, document.path.lastIndexOf("/"));
    const markup = renderMarkdown(document.markdown, directory).markup;

    it(`renders ${document.path} without throwing, and with its headings`, () => {
      expect(markup.length).toBeGreaterThan(1000);
      expect(headings(document.markdown).length).toBeGreaterThan(2);
      for (const heading of headings(document.markdown)) {
        expect(markup).toContain(`id="${heading.id}"`);
      }
    });

    it(`serves ${document.path} under the content-security-policy`, () => {
      expect(markup).not.toContain("<script");
      expect(markup).not.toContain(" style=");
      expect(markup).not.toContain(" onclick=");
      expect(markup).not.toContain("javascript:");
    });

    /**
     * Every `<` in the output has to be one this renderer wrote. The documents
     * are full of `<entry id>` and `<seal seq, 8 digits>` placeholders, so the
     * check is not decorative: strip the tags the renderer emits, and no angle
     * bracket from the source may be left unescaped.
     */
    it(`escapes every angle bracket ${document.path} carries`, () => {
      const withoutTags = markup.replace(/<\/?[a-z][a-z0-9]*(?:\s[^>]*)?\/?>/g, "");
      expect(withoutTags).not.toContain("<");
      expect(withoutTags).not.toContain(">");
    });
  }

  it("links the summary's cross-reference at the whitepaper page", () => {
    const markup = renderMarkdown(SUMMARY_MARKDOWN, "paper").markup;
    expect(markup).toContain(`<a href="/docs/whitepaper">WHITEPAPER.md</a>`);
  });
});

/**
 * The markdown renderer the three served documents are drawn with (D-104).
 *
 * The whitepaper, its summary and the fork guide are written in markdown in
 * this repository, and they are the record of what this thing claims to be. A
 * reader should not have to leave for GitHub to read them, so the Worker serves
 * them — which means turning somebody's markdown into markup under a
 * content-security-policy that allows no script and no inline style at all.
 *
 * So this renderer emits classes from src/ui/styles.ts and nothing else, and it
 * never passes a byte of the source through unescaped: every text run goes
 * through `escapeHtml`, raw HTML in the source is escaped rather than emitted,
 * and a link target that is not http or https is not an anchor. `javascript:`
 * is well-formed markdown and well-formed markup, and the only defence against
 * it is refusing to build the anchor.
 *
 * Pure and total: no clock, no network, no store, no throw. What it does not
 * understand is a paragraph, which is the fallback that cannot lose text.
 */

import { escapeHtml, raw, safeHref, type Safe } from "./html.js";

/**
 * Where a relative link that is not one of the three documents lands: the code
 * repository, at the branch the documents themselves are read from. Spelled
 * here rather than imported from a page, because this module is the one that
 * resolves a document's own relative links and a page is not.
 */
const BLOB_BASE = "https://github.com/nomankind-ai/nomankind/blob/main/";

/**
 * The three documents this Worker serves, by the file name a sibling document
 * links them as. A cross-reference between them stays on this site: the reader
 * following it asked for the other document, not for GitHub's view of it.
 */
const SERVED: Readonly<Record<string, string>> = Object.freeze({
  "WHITEPAPER.md": "/docs/whitepaper",
  "SUMMARY.md": "/docs/summary",
  "FORK.md": "/docs/fork",
});

/** One heading of the document, as the strip across the top shows it. */
export interface Heading {
  readonly level: number;
  readonly text: string;
  readonly id: string;
}

interface ListItem {
  text: string;
  children: ListBlock | null;
}

interface ListBlock {
  ordered: boolean;
  items: ListItem[];
}

type Block =
  | { kind: "heading"; level: number; text: string; id: string }
  | { kind: "paragraph"; text: string }
  | { kind: "code"; text: string }
  | { kind: "quote"; paragraphs: string[] }
  | { kind: "rule" }
  | { kind: "list"; list: ListBlock }
  | { kind: "table"; head: string[]; rows: string[][] };

const FENCE = /^\s*```/;
const HEADING = /^(#{1,4})\s+(.*?)\s*#*\s*$/;
const RULE = /^ {0,3}(?:-{3,}|\*{3,}|_{3,})\s*$/;
const QUOTE = /^ {0,3}>\s?(.*)$/;
const TOP_ITEM = /^ {0,1}(?:([-*+])|(\d+)[.)])\s+(.*)$/;
const NESTED_ITEM = /^ {2,5}(?:([-*+])|(\d+)[.)])\s+(.*)$/;
const TABLE_DELIMITER = /^\s*\|?[\s:|-]*-[\s:|-]*\|[\s:|-]*$/;

/** The text of a heading with its inline markers taken off, for the slug. */
function plain(text: string): string {
  return text
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[`*_]/g, "");
}

/** `The release window` becomes `the-release-window`. */
function slugify(text: string): string {
  const slug = plain(text)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug === "" ? "section" : slug;
}

/**
 * The id a heading gets, deduplicated with a numeric suffix.
 *
 * Two headings can carry the same words — a document with "Money" under two
 * sections is not a mistake — and two elements with one id is a page whose
 * anchors take a reader to whichever came first. So the second occurrence is
 * `-2`, the third `-3`, in document order.
 */
function uniqueId(text: string, seen: Map<string, number>): string {
  const base = slugify(text);
  const count = (seen.get(base) ?? 0) + 1;
  seen.set(base, count);
  return count === 1 ? base : `${base}-${count}`;
}

/** One row of a pipe table, split on the pipes that are not inside code. */
function splitRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  const cells: string[] = [];
  let cell = "";
  let inCode = false;
  for (const ch of trimmed) {
    if (ch === "`") inCode = !inCode;
    if (ch === "|" && !inCode) {
      cells.push(cell.trim());
      cell = "";
      continue;
    }
    cell += ch;
  }
  cells.push(cell.trim());
  return cells;
}

/** True when the line opens a block that a paragraph must not swallow. */
function startsBlock(line: string): boolean {
  return (
    FENCE.test(line) ||
    HEADING.test(line) ||
    RULE.test(line) ||
    QUOTE.test(line) ||
    TOP_ITEM.test(line) ||
    line.trim().startsWith("|")
  );
}

/** The list that begins at `start`, and the line after it. */
function readList(lines: string[], start: number): { list: ListBlock; next: number } {
  const list: ListBlock = { ordered: false, items: [] };
  let index = start;
  let first = true;
  while (index < lines.length) {
    const line = lines[index] ?? "";
    if (line.trim() === "") break;
    const nested = NESTED_ITEM.exec(line);
    const top = nested === null ? TOP_ITEM.exec(line) : null;
    if (top !== null) {
      if (first) {
        list.ordered = top[1] === undefined;
        first = false;
      }
      list.items.push({ text: top[3] ?? "", children: null });
      index += 1;
      continue;
    }
    const open = list.items[list.items.length - 1];
    if (open === undefined) break;
    if (nested !== null) {
      const children = open.children ?? {
        ordered: nested[1] === undefined,
        items: [],
      };
      children.items.push({ text: nested[3] ?? "", children: null });
      open.children = children;
      index += 1;
      continue;
    }
    if (!/^\s+\S/.test(line)) break;
    // An indented line that is not a marker continues the item it sits under,
    // which is the deepest one open: a wrapped sentence, not a new point.
    const deepest =
      open.children === null
        ? open
        : open.children.items[open.children.items.length - 1] ?? open;
    deepest.text = `${deepest.text} ${line.trim()}`;
    index += 1;
  }
  return { list, next: index };
}

/** The document as blocks, in order, with every heading's id already decided. */
function parse(md: string): Block[] {
  const lines = md.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  const seen = new Map<string, number>();
  let index = 0;

  while (index < lines.length) {
    const line = lines[index] ?? "";
    if (line.trim() === "") {
      index += 1;
      continue;
    }

    if (FENCE.test(line)) {
      const body: string[] = [];
      index += 1;
      while (index < lines.length && !FENCE.test(lines[index] ?? "")) {
        body.push(lines[index] ?? "");
        index += 1;
      }
      // The closing fence, when the document has one. A document that ends
      // inside a fence still renders: the block is what was collected.
      if (index < lines.length) index += 1;
      blocks.push({ kind: "code", text: body.join("\n") });
      continue;
    }

    const heading = HEADING.exec(line);
    if (heading !== null) {
      const text = heading[2] ?? "";
      blocks.push({
        kind: "heading",
        level: (heading[1] ?? "#").length,
        text,
        id: uniqueId(text, seen),
      });
      index += 1;
      continue;
    }

    if (RULE.test(line)) {
      blocks.push({ kind: "rule" });
      index += 1;
      continue;
    }

    const quoted = QUOTE.exec(line);
    if (quoted !== null) {
      const paragraphs: string[] = [];
      let current: string[] = [];
      while (index < lines.length) {
        const match = QUOTE.exec(lines[index] ?? "");
        if (match === null) break;
        const text = (match[1] ?? "").trim();
        if (text === "") {
          if (current.length > 0) paragraphs.push(current.join(" "));
          current = [];
        } else current.push(text);
        index += 1;
      }
      if (current.length > 0) paragraphs.push(current.join(" "));
      blocks.push({ kind: "quote", paragraphs });
      continue;
    }

    if (line.trim().startsWith("|") && TABLE_DELIMITER.test(lines[index + 1] ?? "")) {
      const head = splitRow(line);
      index += 2;
      const rows: string[][] = [];
      while (index < lines.length && (lines[index] ?? "").trim().startsWith("|")) {
        rows.push(splitRow(lines[index] ?? ""));
        index += 1;
      }
      blocks.push({ kind: "table", head, rows });
      continue;
    }

    if (TOP_ITEM.test(line)) {
      const read = readList(lines, index);
      blocks.push({ kind: "list", list: read.list });
      index = read.next;
      continue;
    }

    const paragraph: string[] = [line.trim()];
    index += 1;
    while (index < lines.length) {
      const next = lines[index] ?? "";
      if (next.trim() === "" || startsBlock(next)) break;
      paragraph.push(next.trim());
      index += 1;
    }
    // A hard line break inside a paragraph is a break in the source file and
    // not in the sentence, so the lines are joined with one space.
    blocks.push({ kind: "paragraph", text: paragraph.join(" ") });
  }

  return blocks;
}

/**
 * Where a link target goes, or null when it may not become an anchor.
 *
 * The refusal is the important half. Escaping is no defence in a href — a
 * `javascript:` URL is perfectly well-formed — so only http and https survive
 * as absolute targets, the three served documents map onto this site, and every
 * other relative path is resolved against the document's own directory and
 * pointed at the code repository, where it is a file that exists.
 */
function targetFor(href: string, dir: string): string | null {
  if (href === "") return null;
  if (href.startsWith("#")) return href;
  if (/^https?:\/\//i.test(href)) return safeHref(href);
  // Any other scheme — javascript:, data:, mailto: — is not a relative path and
  // is not one of the two we link.
  if (/^[a-z][a-z0-9+.-]*:/i.test(href)) return null;

  const hash = href.indexOf("#");
  const path = hash === -1 ? href : href.slice(0, hash);
  const fragment = hash === -1 ? "" : href.slice(hash);
  const resolved = resolvePath(dir, path);
  const name = resolved.slice(resolved.lastIndexOf("/") + 1);
  const served = SERVED[name];
  if (served !== undefined) return `${served}${fragment}`;
  return safeHref(`${BLOB_BASE}${resolved}${fragment}`);
}

/** A relative path against the directory the document itself lives in. */
function resolvePath(dir: string, target: string): string {
  const segments = target.startsWith("/")
    ? []
    : dir.split("/").filter((each) => each !== "" && each !== ".");
  for (const segment of target.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") segments.pop();
    else segments.push(segment);
  }
  return segments.join("/");
}

const CODE_SPAN = /(`+)([\s\S]*?)\1/y;
const LINK = /\[([^\]]*)\]\(\s*([^()\s]*)\s*\)/y;
/**
 * An autolink: a bare URL in angle brackets, which is how the whitepaper's
 * references cite their sources. Only http and https match, so everything else
 * between angle brackets — `<entry id>`, `<seal seq>`, a raw tag — falls
 * through to being escaped one character at a time, which is the whole point.
 */
const AUTOLINK = /<(https?:\/\/[^\s<>]+)>/iy;
const STRONG = /\*\*([\s\S]+?)\*\*/y;
const EM_STAR = /\*([^\s*][\s\S]*?)\*/y;
const EM_UNDER = /_([^\s_][\s\S]*?)_(?![A-Za-z0-9_])/y;

/** An anchor, with the rel a target outside this site gets. */
function anchor(target: string, label: string): string {
  const external = /^https?:/i.test(target);
  const rel = external ? ` rel="noopener noreferrer nofollow"` : "";
  return `<a href="${escapeHtml(target)}"${rel}>${label}</a>`;
}

/**
 * One run of markdown text as markup. Code first, then links, then strong, then
 * emphasis: a backtick span is literal, so nothing inside it is markup, and
 * `**` has to be tried before `*` or every strong would read as two emphases.
 *
 * Everything that matches nothing is escaped, one character at a time, which is
 * what makes raw HTML in the source come back as text.
 */
function inline(text: string, dir: string): string {
  let out = "";
  let index = 0;
  while (index < text.length) {
    const ch = text[index] ?? "";

    if (ch === "`") {
      CODE_SPAN.lastIndex = index;
      const code = CODE_SPAN.exec(text);
      if (code !== null) {
        out += `<code>${escapeHtml((code[2] ?? "").trim())}</code>`;
        index = CODE_SPAN.lastIndex;
        continue;
      }
    }

    if (ch === "[") {
      LINK.lastIndex = index;
      const link = LINK.exec(text);
      if (link !== null) {
        const label = inline(link[1] ?? "", dir);
        const target = targetFor(link[2] ?? "", dir);
        out += target === null ? label : anchor(target, label);
        index = LINK.lastIndex;
        continue;
      }
    }

    if (ch === "<") {
      AUTOLINK.lastIndex = index;
      const auto = AUTOLINK.exec(text);
      if (auto !== null) {
        const url = auto[1] ?? "";
        const target = targetFor(url, dir);
        if (target !== null) {
          out += anchor(target, escapeHtml(url));
          index = AUTOLINK.lastIndex;
          continue;
        }
      }
    }

    if (ch === "*" && text.startsWith("**", index)) {
      STRONG.lastIndex = index;
      const strong = STRONG.exec(text);
      if (strong !== null) {
        out += `<strong>${inline(strong[1] ?? "", dir)}</strong>`;
        index = STRONG.lastIndex;
        continue;
      }
    }

    if (ch === "*") {
      EM_STAR.lastIndex = index;
      const em = EM_STAR.exec(text);
      if (em !== null) {
        out += `<em>${inline(em[1] ?? "", dir)}</em>`;
        index = EM_STAR.lastIndex;
        continue;
      }
    }

    // An underscore is emphasis only between word boundaries: `last_seq` and
    // `prev_hash` are identifiers this record writes constantly, and a renderer
    // that italicised the middle of one would be rewriting the log's own names.
    if (ch === "_" && !/[A-Za-z0-9_]/.test(text[index - 1] ?? "")) {
      EM_UNDER.lastIndex = index;
      const em = EM_UNDER.exec(text);
      if (em !== null) {
        out += `<em>${inline(em[1] ?? "", dir)}</em>`;
        index = EM_UNDER.lastIndex;
        continue;
      }
    }

    out += escapeHtml(ch);
    index += 1;
  }
  return out;
}

/** One list, and the one level of nesting under it. */
function renderList(list: ListBlock, dir: string): string {
  const tag = list.ordered ? "ol" : "ul";
  const items = list.items
    .map((item) => {
      const children =
        item.children === null ? "" : renderList(item.children, dir);
      return `<li>${inline(item.text, dir)}${children}</li>`;
    })
    .join("");
  return `<${tag}>${items}</${tag}>`;
}

/** One pipe table, kept in its own scroller so the page never scrolls sideways. */
function renderTable(head: string[], rows: string[][], dir: string): string {
  const header = head.map((cell) => `<th>${inline(cell, dir)}</th>`).join("");
  const body = rows
    .map(
      (row) =>
        `<tr>${row.map((cell) => `<td class="prose">${inline(cell, dir)}</td>`).join("")}</tr>`,
    )
    .join("");
  return (
    `<div class="table-wrap"><table class="table">` +
    `<thead><tr>${header}</tr></thead><tbody>${body}</tbody>` +
    `</table></div>`
  );
}

function renderBlock(block: Block, dir: string): string {
  switch (block.kind) {
    case "heading":
      return `<h${block.level} id="${escapeHtml(block.id)}">${inline(block.text, dir)}</h${block.level}>`;
    case "paragraph":
      return `<p class="prose">${inline(block.text, dir)}</p>`;
    case "code":
      return `<pre class="block">${escapeHtml(block.text)}</pre>`;
    case "quote":
      return (
        `<blockquote class="note">` +
        block.paragraphs
          .map((each) => `<p class="prose">${inline(each, dir)}</p>`)
          .join("") +
        `</blockquote>`
      );
    case "rule":
      return `<hr />`;
    case "list":
      return renderList(block.list, dir);
    case "table":
      return renderTable(block.head, block.rows, dir);
  }
}

/** How a document is rendered when a page around it supplies the heading. */
export interface RenderOptions {
  /**
   * The heading the page has already printed as its own `<h1>`, when it has.
   *
   * A page has one `<h1>`. A document rendered whole under one gives it a
   * second — the whitepaper gave it fourteen, every section drawn at the
   * page-title size — and where the document's title is the page's title the
   * reader is told the same thing twice, which is what /docs/fork did. So with
   * this set, every heading is rendered one level down: a section becomes an
   * `<h2>` under the page's title and everything below it an `<h3>`, which is
   * as deep as this renderer goes. And when the document opens with a level-1
   * heading that says exactly what the page already said, that one is dropped
   * rather than repeated. The ids are untouched either way, because the strip
   * across the top of the page anchors at them.
   */
  readonly underTitle?: string;
}

/** The blocks as the body of a page whose own `<h1>` is `title`. */
function underTitle(blocks: Block[], title: string): Block[] {
  const body: Block[] = [];
  let first = true;
  for (const block of blocks) {
    if (block.kind !== "heading") {
      body.push(block);
      continue;
    }
    if (first) {
      first = false;
      // The document's own title, where it is the one the page has printed.
      if (block.level === 1 && plain(block.text).trim() === title.trim()) {
        continue;
      }
    }
    body.push({ ...block, level: Math.min(block.level + 1, 3) });
  }
  return body;
}

/**
 * A markdown document as markup.
 *
 * `dir` is the directory the document itself lives in, which is what a relative
 * link in it is resolved against; the default is the repository root, which is
 * where a document with no directory of its own sits.
 */
export function renderMarkdown(
  md: string,
  dir = "",
  options: RenderOptions = {},
): Safe {
  const blocks = parse(md);
  const body =
    options.underTitle === undefined
      ? blocks
      : underTitle(blocks, options.underTitle);
  return raw(body.map((block) => renderBlock(block, dir)).join("\n"));
}

/**
 * The document's level-1 and level-2 headings, with the ids `renderMarkdown`
 * gave them, in document order. Deeper headings are left out on purpose: these
 * are a way into the document, and a list with every heading in it is a second
 * copy of the document.
 */
export function headings(md: string): Heading[] {
  const found: Heading[] = [];
  for (const block of parse(md)) {
    if (block.kind !== "heading") continue;
    if (block.level > 2) continue;
    found.push({ level: block.level, text: plain(block.text), id: block.id });
  }
  return found;
}

/**
 * The document's own top-level sections — what the strip across the top of the
 * page lists.
 *
 * Which level that is depends on the document. The whitepaper writes its
 * thirteen sections as level-1 headings under a level-1 title, so its level-2
 * headings are subsections and a strip of them lists fifteen things that are
 * not the paper's sections. The summary and the fork guide write one level-1
 * title and their sections beneath it. So: the level-1 headings after the
 * title when there is more than one, and otherwise the level-2 headings.
 */
export function sections(md: string): Heading[] {
  const found = headings(md);
  const top = found.filter((each) => each.level === 1);
  return top.length > 1 ? top.slice(1) : found.filter((each) => each.level === 2);
}

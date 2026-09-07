/**
 * The pure-TypeScript HTML extractor of snapshot normalization norm-v1.2
 * (decision D-012), steps E2 to E6 of the published rule set.
 *
 * Whitepaper section 4: a snapshot's hash is taken over the page's extracted
 * content under a published, versioned rule, never over raw bytes. This module
 * is that extraction: tokenize, remove elements, scope, turn tags into text,
 * decode character references. It is pure and synchronous, has no dependency on
 * a DOM, and never touches the network or the clock.
 *
 * The output is deliberately NOT normalized: normalizeText (step 4) is the
 * caller's next step, so extraction and normalization stay testable apart.
 */

/**
 * E3. Elements removed with their content, before scoping. Exported so the norm
 * document and the kernel cannot drift apart.
 */
export const REMOVED_ELEMENTS: readonly string[] = Object.freeze([
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

/** E5. Elements whose start and end tags each become a newline. */
export const BLOCK_ELEMENTS: readonly string[] = Object.freeze([
  "address",
  "article",
  "blockquote",
  "caption",
  "dd",
  "details",
  "dialog",
  "div",
  "dl",
  "dt",
  "fieldset",
  "figcaption",
  "figure",
  "form",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "hgroup",
  "hr",
  "legend",
  "li",
  "main",
  "ol",
  "p",
  "pre",
  "section",
  "summary",
  "table",
  "tbody",
  "tfoot",
  "thead",
  "tr",
  "ul",
]);

const REMOVED = new Set(REMOVED_ELEMENTS);
const BLOCK = new Set(BLOCK_ELEMENTS);

/** script and style end at the first end tag of the same name, as in browsers. */
const RAW_TEXT = new Set(["script", "style"]);

interface TextToken {
  readonly kind: "text";
  readonly text: string;
}

interface TagToken {
  readonly kind: "tag";
  readonly name: string;
  readonly end: boolean;
  readonly selfClosing: boolean;
}

type Token = TextToken | TagToken;

function isAsciiLetter(char: string | undefined): boolean {
  if (char === undefined) {
    return false;
  }
  return (char >= "a" && char <= "z") || (char >= "A" && char <= "Z");
}

function asciiLower(value: string): string {
  let out = "";
  for (const char of value) {
    out += char >= "A" && char <= "Z" ? char.toLowerCase() : char;
  }
  return out;
}

function isNameBreak(char: string): boolean {
  return (
    char === "/" ||
    char === ">" ||
    char === " " ||
    char === "\t" ||
    char === "\n" ||
    char === "\r" ||
    char === "\f" ||
    char === "\v"
  );
}

/**
 * E2. Tokenize, left to right. Comments, markup declarations and processing
 * instructions are dropped here; an unterminated tag is dropped and ends the
 * document; any other "<" is text.
 */
function tokenize(html: string): Token[] {
  const tokens: Token[] = [];
  let text = "";
  const flush = (): void => {
    if (text.length > 0) {
      tokens.push({ kind: "text", text });
      text = "";
    }
  };

  let i = 0;
  while (i < html.length) {
    const char = html[i]!;
    if (char !== "<") {
      text += char;
      i += 1;
      continue;
    }

    if (html.startsWith("<!--", i)) {
      flush();
      const close = html.indexOf("-->", i + 4);
      i = close === -1 ? html.length : close + 3;
      continue;
    }

    if (html.startsWith("<!", i) || html.startsWith("<?", i)) {
      flush();
      const close = html.indexOf(">", i + 2);
      i = close === -1 ? html.length : close + 1;
      continue;
    }

    let nameStart = i + 1;
    let end = false;
    if (html[nameStart] === "/") {
      end = true;
      nameStart += 1;
    }
    if (!isAsciiLetter(html[nameStart])) {
      text += char;
      i += 1;
      continue;
    }

    let cursor = nameStart;
    while (cursor < html.length && !isNameBreak(html[cursor]!)) {
      cursor += 1;
    }
    const name = asciiLower(html.slice(nameStart, cursor));

    let quote: string | null = null;
    let close = -1;
    let scan = cursor;
    while (scan < html.length) {
      const inner = html[scan]!;
      if (quote !== null) {
        if (inner === quote) {
          quote = null;
        }
      } else if (inner === '"' || inner === "'") {
        quote = inner;
      } else if (inner === ">") {
        close = scan;
        break;
      }
      scan += 1;
    }

    flush();
    if (close === -1) {
      // An unterminated tag runs to the end of the document and is dropped.
      i = html.length;
      continue;
    }

    const body = html.slice(cursor, close).replace(/[\s]+$/u, "");
    const selfClosing = !end && body.endsWith("/");
    tokens.push({ kind: "tag", name, end, selfClosing });
    i = close + 1;
  }

  flush();
  return tokens;
}

/**
 * E3. Remove each listed element with its content, over the whole document and
 * before scoping. script and style end at the first end tag of the same name;
 * the others count nesting. A self-closing start tag drops only itself, and a
 * start tag with no matching end tag runs to the end of the document.
 */
function removeElements(tokens: readonly Token[]): Token[] {
  const kept: Token[] = [];
  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token.kind === "tag" && !token.end && REMOVED.has(token.name)) {
      if (token.selfClosing) {
        i += 1;
        continue;
      }
      const raw = RAW_TEXT.has(token.name);
      let depth = 1;
      let scan = i + 1;
      while (scan < tokens.length) {
        const inner = tokens[scan]!;
        if (inner.kind === "tag" && inner.name === token.name) {
          if (inner.end) {
            depth -= 1;
            if (depth === 0) {
              break;
            }
          } else if (!raw && !inner.selfClosing) {
            depth += 1;
          }
        }
        scan += 1;
      }
      i = scan + 1;
      continue;
    }
    kept.push(token);
    i += 1;
  }
  return kept;
}

/**
 * The content of every outermost element of the given name, in document order.
 * An element nested inside a collected one is not collected again; an element
 * with no matching end tag runs to the end of the document; a self-closing
 * start tag is an element with empty content.
 */
function outermostContents(
  tokens: readonly Token[],
  name: string,
): Token[][] {
  const found: Token[][] = [];
  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i]!;
    if (token.kind === "tag" && !token.end && token.name === name) {
      if (token.selfClosing) {
        found.push([]);
        i += 1;
        continue;
      }
      let depth = 1;
      let scan = i + 1;
      while (scan < tokens.length) {
        const inner = tokens[scan]!;
        if (inner.kind === "tag" && inner.name === name) {
          if (inner.end) {
            depth -= 1;
            if (depth === 0) {
              break;
            }
          } else if (!inner.selfClosing) {
            depth += 1;
          }
        }
        scan += 1;
      }
      found.push(tokens.slice(i + 1, Math.min(scan, tokens.length)));
      i = scan + 1;
      continue;
    }
    i += 1;
  }
  return found;
}

/**
 * E5. Tags to text, within the scope. br becomes a newline, td and th a single
 * space, block elements a newline, and every other tag nothing.
 */
function renderTokens(tokens: readonly Token[]): string {
  let out = "";
  for (const token of tokens) {
    if (token.kind === "text") {
      out += token.text;
      continue;
    }
    if (token.name === "br" && !token.end) {
      out += "\n";
      continue;
    }
    if (token.name === "td" || token.name === "th") {
      out += " ";
      continue;
    }
    if (BLOCK.has(token.name)) {
      out += "\n";
    }
  }
  return out;
}

/** E4. Scope: main, else article, else body, else the whole document. */
function scopedText(tokens: readonly Token[]): string {
  for (const name of ["main", "article", "body"]) {
    const contents = outermostContents(tokens, name);
    if (contents.length > 0) {
      return contents.map(renderTokens).join("\n");
    }
  }
  return renderTokens(tokens);
}

const NAMED_REFERENCES: ReadonlyMap<string, string> = new Map([
  ["&amp;", "&"],
  ["&lt;", "<"],
  ["&gt;", ">"],
  ["&quot;", '"'],
  ["&apos;", "'"],
  ["&nbsp;", " "],
]);

const REPLACEMENT = "\uFFFD";

function fromCodePoint(codePoint: number): string {
  if (codePoint === 0 || codePoint > 0x10ffff) {
    return REPLACEMENT;
  }
  if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
    return REPLACEMENT;
  }
  if (codePoint === 0x00a0) {
    return " ";
  }
  return String.fromCodePoint(codePoint);
}

const NUMERIC = /&#(?:([0-9]+)|[xX]([0-9a-fA-F]+));/y;

/**
 * E6. Character references, single pass: decoded output is never decoded again,
 * so "&amp;lt;" yields "&lt;". Unknown names and references without the closing
 * semicolon stay literal. Every literal U+00A0 then becomes a space.
 */
function decodeReferences(text: string): string {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const char = text[i]!;
    if (char !== "&") {
      out += char;
      i += 1;
      continue;
    }

    let named: string | undefined;
    for (const [reference, value] of NAMED_REFERENCES) {
      if (text.startsWith(reference, i)) {
        named = value;
        out += value;
        i += reference.length;
        break;
      }
    }
    if (named !== undefined) {
      continue;
    }

    NUMERIC.lastIndex = i;
    const match = NUMERIC.exec(text);
    if (match !== null) {
      const decimal = match[1];
      const hex = match[2];
      const codePoint =
        decimal !== undefined
          ? Number.parseInt(decimal, 10)
          : Number.parseInt(hex!, 16);
      out += fromCodePoint(codePoint);
      i = NUMERIC.lastIndex;
      continue;
    }

    out += char;
    i += 1;
  }
  return out.replace(/\u00a0/gu, " ");
}

/**
 * Extract a page's content under norm-v1.2: steps E2 to E6. The result is the
 * text after character-reference decoding, before normalizeText.
 */
export function extractHtml(html: string): string {
  return decodeReferences(scopedText(removeElements(tokenize(html))));
}

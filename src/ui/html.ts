/**
 * The one place markup is built, and the one place it is escaped.
 *
 * The browsing UI is server-rendered and carries no client-side script at all:
 * the content-security-policy below says `default-src 'none'` and never names a
 * script source, so a page that tried to run one would be blocked by the
 * browser rather than trusted by it. That is the point. Whitepaper Section 3,
 * The log: a reader has to be able to check an entry, and a page that could
 * execute a claim's own text is a page that cannot be checked.
 *
 * So there is exactly one way to compose markup here — the `html` tagged
 * template — and it escapes every interpolation unless the value is `Safe`,
 * which only `raw` and `html` itself produce. A claim, a subject, an operator
 * id, a reason: all of it is somebody else's text, and none of it can become
 * markup by accident.
 *
 * Pure. Nothing here reads a binding, a clock or a database, and nothing here
 * imports from src/worker/: every function is a function of its arguments, so a
 * page can be rendered and asserted on without a Worker.
 */

import { APP_CSS } from "./styles.js";
import type { PageContext } from "./types.js";

/** An em dash, for a field that has no value. */
const EM_DASH = "—";

/** A single-character ellipsis, for a hash shown short. */
const ELLIPSIS = "…";

/**
 * Markup that is already safe to write into the document.
 *
 * Branded rather than a bare string on purpose: `html` has to be able to tell,
 * at run time, the difference between markup it built and text that arrived
 * from outside, and two strings are indistinguishable. Only `raw` and `html`
 * make one, so the only way a value becomes markup is by going through them.
 */
export interface Safe {
  /** The brand. A plain string can never satisfy it. */
  readonly safeMarkup: true;
  readonly markup: string;
}

/** Mark a string as markup that must not be escaped. */
export function raw(markup: string): Safe {
  return { safeMarkup: true, markup };
}

function isSafe(value: unknown): value is Safe {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { safeMarkup?: unknown }).safeMarkup === true &&
    typeof (value as { markup?: unknown }).markup === "string"
  );
}

/**
 * Escape the five characters that can end an element, an attribute or a
 * comment. `&` goes first, or the escapes escape each other.
 *
 * null and undefined render as nothing rather than as the words "null" and
 * "undefined": a missing field is missing, and a page that printed the word
 * would be stating something the log does not say. Numbers and booleans render
 * as their text, because a false and a zero are values.
 */
export function escapeHtml(value: unknown): string {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** One interpolated value, escaped unless it is already markup. */
function interpolate(value: unknown): string {
  if (isSafe(value)) return value.markup;
  if (Array.isArray(value)) return value.map(interpolate).join("");
  return escapeHtml(value);
}

/**
 * The tagged template every page composes with. Every interpolation is escaped
 * except a `Safe` value, and an array is joined without a separator so a list of
 * rows can be interpolated where a row goes.
 */
export function html(
  strings: TemplateStringsArray,
  ...values: unknown[]
): Safe {
  let out = strings[0] ?? "";
  for (let index = 0; index < values.length; index += 1) {
    out += interpolate(values[index]);
    out += strings[index + 1] ?? "";
  }
  return raw(out);
}

/**
 * A URL, but only if it is one the page may link to.
 *
 * Citations arrive from submitters, so a citation is untrusted input in a link
 * position — the one place escaping alone is not enough, because `javascript:`
 * is perfectly well-formed markup. Only http and https come back; everything
 * else, a relative path included, is null and the caller renders plain text.
 */
export function safeHref(url: unknown): string | null {
  if (typeof url !== "string" || url.length === 0) return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  return url;
}

/**
 * A hash shown short: the `sha256:` prefix dropped and the first twelve hex
 * characters, then an ellipsis. The full value belongs in the caller's `title`
 * attribute — a hash a reader cannot copy in full is a hash they cannot check.
 */
export function shortHash(value: string): string {
  const hex = value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
  return hex.length <= 12 ? hex : `${hex.slice(0, 12)}${ELLIPSIS}`;
}

/** An ISO instant as `2026-09-09 04:49:44Z`, or an em dash for null. */
export function fmtInstant(iso: string | null): string {
  if (iso === null) return EM_DASH;
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  const text = at.toISOString();
  return `${text.slice(0, 10)} ${text.slice(11, 19)}Z`;
}

/** The date part of an instant or a date, or an em dash for null. */
export function fmtDate(iso: string | null): string {
  if (iso === null) return EM_DASH;
  if (/^\d{4}-\d{2}-\d{2}/.test(iso)) return iso.slice(0, 10);
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  return at.toISOString().slice(0, 10);
}

/**
 * The class that colours a status. The visual system (D-018, direction C) has
 * three accents and five statuses, so the mapping is named here once rather
 * than guessed at in each page. An unknown status gets the neutral class rather
 * than a colour that would claim something about it.
 */
export function statusClass(status: string): string {
  switch (status) {
    case "verified":
      return "s-verified";
    case "superseded":
      return "s-superseded";
    case "draft":
      return "s-draft";
    case "rejected":
      return "s-rejected";
    case "overturned":
      return "s-overturned";
    default:
      return "s-other";
  }
}

/** A bordered mono badge: a status, a tier, a category. */
export function badge(kind: string, label: string): Safe {
  return html`<span class="badge ${kind}">${label}</span>`;
}

/**
 * A link. An external one opens in a new tab and carries
 * `rel="noopener noreferrer nofollow"`: a citation is somebody else's URL, and
 * the log neither vouches for it nor passes it a referrer. A href that
 * `safeHref` refuses renders as plain text, so the label is never lost.
 */
export function link(href: string, label: string, external = false): Safe {
  const safe = safeHref(href);
  if (safe === null) return html`${label}`;
  return external
    ? html`<a href="${safe}" target="_blank" rel="noopener noreferrer nofollow">${label}</a>`
    : html`<a href="${safe}">${label}</a>`;
}

/**
 * A stylesheet's version, derived from the stylesheet itself.
 *
 * The two sheets are served with an hour of public cache (see `cssResponse`),
 * which is right for bytes that are the same for every reader and say nothing
 * about the log — but it also means a returning browser can hold a stale sheet
 * for an hour after a deploy, and a page whose rules are an hour behind its
 * markup is a page that is drawn wrong. So the link carries the sheet's own
 * content in its href: change one rule and the URL changes, and the browser
 * fetches rather than reuses. Nothing here is a secret and nothing here is
 * checked, so this is FNV-1a, 32 bits — deterministic, and synchronous, which
 * WebCrypto is not and a module-load constant cannot wait for.
 */
export function assetVersion(content: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < content.length; index += 1) {
    hash ^= content.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

/**
 * The href a page links a stylesheet by: the path, then the version as a query.
 * The query form rather than a versioned filename on purpose — the route matches
 * on the pathname, so the plain path and every versioned form are the same
 * route and there is nothing to keep in step.
 */
export function versionedHref(path: string, content: string): string {
  return `${path}?v=${assetVersion(content)}`;
}

/** The app stylesheet's link, computed once when this module loads. */
export const APP_CSS_HREF = versionedHref("/static/app.css", APP_CSS);

/** The repository and the paper, linked from the header and the footer. */
const REPOSITORY_URL = "https://github.com/nomankind-ai/nomankind";
const PAPER_URL =
  "https://github.com/nomankind-ai/nomankind/blob/main/paper/WHITEPAPER.md";

/**
 * The nav, in the order the prototype shows it. Paper is external because the
 * paper is the record of what this thing claims to be and it lives with the
 * code, not in a page that could paraphrase it.
 */
const NAV: readonly { readonly href: string; readonly label: string; readonly external?: boolean }[] =
  [
    { href: "/entries", label: "Entries" },
    { href: "/operators", label: "Operators" },
    { href: "/policy", label: "Policy" },
    { href: "/api", label: "API" },
    { href: "/genesis", label: "Genesis" },
    { href: PAPER_URL, label: "Paper", external: true },
  ];

/** The wordmark's inline SVG. No emoji anywhere in this UI (D-018). */
const WORDMARK_ICON = raw(
  `<svg class="mark" width="20" height="20" viewBox="0 0 20 20" fill="none" ` +
    `stroke="currentColor" stroke-width="1.5" aria-hidden="true">` +
    `<rect x="3" y="3" width="14" height="14" rx="2"></rect>` +
    `<path d="M7 10h6M10 7v6"></path></svg>`,
);

function navItems(path: string): Safe[] {
  return NAV.map((item) => {
    const active = !item.external && path.startsWith(item.href);
    const classes = active ? "nav nav-active" : "nav";
    return item.external === true
      ? html`<a class="${classes}" href="${item.href}" target="_blank" rel="noopener noreferrer nofollow">${item.label}</a>`
      : html`<a class="${classes}" href="${item.href}">${item.label}</a>`;
  });
}

/**
 * The whole document: the head, the sticky header, the page's body, the footer.
 *
 * There is no `<script>` here and there is no inline `style` attribute either —
 * the CSP forbids both, so the prototype's look is expressed entirely as classes
 * in src/ui/styles.ts. The stylesheet is served from this Worker at
 * /static/app.css, linked with the version suffix `assetVersion` derives from
 * the sheet itself so an hour of cache cannot outlive a rule change; only the
 * font stylesheet is fetched from elsewhere, and the CSP names exactly the two
 * Google hosts it needs.
 */
export function layout(
  ctx: PageContext,
  options: { title: string; body: Safe; description?: string },
): string {
  const description =
    options.description === undefined
      ? raw("")
      : html`<meta name="description" content="${options.description}" />`;
  const document = html`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${options.title} · nomankind</title>
    ${description}
    <link
      rel="stylesheet"
      href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap"
    />
    <link rel="stylesheet" href="${APP_CSS_HREF}" />
  </head>
  <body>
    <header class="header">
      <a class="wordmark" href="/">
        ${WORDMARK_ICON}
        <span class="wordmark-text">nomankind</span>
      </a>
      <span class="env mono">${ctx.environment}</span>
      <nav class="nav-list">${navItems(ctx.path)}</nav>
    </header>
    <main class="main">${options.body}</main>
    <footer class="footer">
      <span class="dim">Apache-2.0. The log and the code are the record.</span>
      <span class="footer-links">
        ${link(REPOSITORY_URL, "Repository", true)}
        ${link(PAPER_URL, "Whitepaper", true)}
      </span>
    </footer>
  </body>
</html>
`;
  return document.markup;
}

/**
 * The content-security-policy every page is served under, verbatim.
 *
 * `default-src 'none'` and no script source at all: this UI has no client-side
 * script, so the browser is told that any script it finds is not ours. Styles
 * come from this origin and Google Fonts, fonts from Google's font host,
 * images only from here or a data URI, forms only back to this origin, and the
 * page may not be framed. Nothing else may load.
 */
export const CONTENT_SECURITY_POLICY =
  "default-src 'none'; style-src 'self' https://fonts.googleapis.com; " +
  "font-src https://fonts.gstatic.com; img-src 'self' data:; " +
  "form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/**
 * Serve a rendered document.
 *
 * `no-store`, because every page is a view of a log that moves and a cached
 * page is a page that lies about the head. `vary: Accept` because the same path
 * answers JSON to a machine and HTML to a browser, and a shared cache that
 * confused the two would hand an agent a web page.
 */
export function htmlResponse(
  document: string,
  status = 200,
  extraHeaders?: Record<string, string>,
): Response {
  const headers = new Headers(extraHeaders);
  headers.set("content-type", "text/html; charset=utf-8");
  headers.set("cache-control", "no-store");
  headers.set("vary", "Accept");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("content-security-policy", CONTENT_SECURITY_POLICY);
  return new Response(document, { status, headers });
}

/**
 * Serve the stylesheet. Cacheable for an hour, unlike a page: the CSS is the
 * same for every reader and says nothing about the log. The hour is safe to
 * hold because the link carries the sheet's own version (`versionedHref`), so a
 * changed rule is a changed URL and a returning browser fetches it at once.
 */
export function cssResponse(css: string): Response {
  return new Response(css, {
    status: 200,
    headers: {
      "content-type": "text/css; charset=utf-8",
      "cache-control": "public, max-age=3600",
      "x-content-type-options": "nosniff",
    },
  });
}

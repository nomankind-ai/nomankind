/**
 * The tab icon, as bytes this Worker serves itself (decision D-114).
 *
 * One file, drawn rather than fetched: the content-security-policy allows an
 * image from this origin or a data URI and nothing else, and an icon pulled off
 * a CDN would be the one thing on the site that a third party could change. So
 * it is an SVG with no external reference of any kind — no font, no image, no
 * stylesheet — which is also why the "n" is two strokes rather than a `<text>`
 * element: a glyph is whatever font the viewer happens to have, and a shape is
 * what it is everywhere.
 *
 * The two colours are src/ui/styles.ts's own, copied here because the palette
 * lives there as CSS custom properties inside the sheet rather than as exported
 * constants: `--bg` (#0f1216), the near-black every page is drawn on, and
 * `--accent` (#7fd1c4), the teal the wordmark and every link hover use. They are
 * checked against the sheet in the tests, so the icon cannot drift from the site
 * it is the icon of.
 *
 * Served at both `/favicon.svg` and `/favicon.ico` (src/worker/pages.ts): a
 * browser that asks for the `.ico` by habit gets this same SVG, which every
 * browser this UI targets renders, rather than a 404 in everybody's console.
 */

/** The near-black the site is drawn on: `--bg` in src/ui/styles.ts. */
export const FAVICON_BACKGROUND = "#0f1216";

/** The teal the wordmark is drawn in: `--accent` in src/ui/styles.ts. */
export const FAVICON_ACCENT = "#7fd1c4";

/**
 * The whole icon: a 64 by 64 rounded square in the app's near-black, with a
 * lowercase "n" in the app's teal — the wordmark's own first letter, at the one
 * size a tab shows.
 */
export const FAVICON_SVG =
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">` +
  `<rect width="64" height="64" rx="14" fill="${FAVICON_BACKGROUND}"/>` +
  `<g fill="none" stroke="${FAVICON_ACCENT}" stroke-width="7" stroke-linecap="round">` +
  `<path d="M23 23v19"/><path d="M23 31a9 9 0 0 1 18 0v11"/>` +
  `</g></svg>\n`;

/** What the icon is served as, and the one hour of cache the stylesheets get. */
export const FAVICON_CONTENT_TYPE = "image/svg+xml";

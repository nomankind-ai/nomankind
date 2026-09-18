/**
 * What the head says to something that is not a reader (decision D-114).
 *
 * Every other UI suite asserts what a person sees. This one asserts the part
 * nobody looking at the page would ever notice was broken: the canonical
 * address, the Open Graph card a shared link renders, the card kind, and the
 * icon. Those four are how the record is quoted somewhere else — in a search
 * result, in a chat unfurl, in a tab strip — and a duplicate canonical or a
 * missing og:title is a defect that renders perfectly.
 *
 * Four pages, on purpose: the landing, which is a document of its own outside
 * `layout`, and three pages that go through `layout` — the home board, an entry,
 * and the Docs hub. The landing and the layout build their heads from the same
 * `seoHead`, and the only way to prove they have not drifted is to run the same
 * assertions over both.
 *
 * Two rules hold everywhere and are asserted on every page here, because this
 * suite is the one that reads whole documents: no script tag, and no inline
 * style attribute. The CSP forbids both, so a page that grew one would be a page
 * the browser draws wrong rather than an error anybody sees.
 */

import { describe, expect, it } from "vitest";
import { SITE_DESCRIPTION } from "../src/ui/html.js";
import type { Entry } from "../src/schema.js";
import { attributionOf } from "../src/attribution.js";
import { confidenceInputs } from "../src/confidence.js";
import type { Sidecar } from "../src/derive.js";
import { renderDocs } from "../src/ui/pages/docs.js";
import { renderEntry } from "../src/ui/pages/entry.js";
import { renderHome } from "../src/ui/pages/home.js";
import { renderLanding } from "../src/ui/pages/landing.js";
import type {
  EntryData,
  HomeData,
  LandingData,
  PageContext,
} from "../src/ui/types.js";

const CANONICAL_ORIGIN = "https://app.nomankind.ai";

const ENTRY_ID = "nmk_00112233445566778899aabbccddeeff";
const HASH =
  "sha256:1111111111111111111111111111111111111111111111111111111111111111";

/** The apex context: the landing at "/" on the deployment's own origin. */
const landingCtx: PageContext = {
  environment: "production",
  path: "/",
  origin: CANONICAL_ORIGIN,
  canonical_origin: CANONICAL_ORIGIN,
};

function ctxAt(path: string): PageContext {
  return {
    environment: "production",
    path,
    origin: CANONICAL_ORIGIN,
    canonical_origin: CANONICAL_ORIGIN,
  };
}

const landingData: LandingData = {
  seals: [
    {
      seq: 288,
      hash: HASH,
      sealedAt: "2026-09-12T04:49:44.000Z",
      witnessed: true,
      events: 11,
    },
  ],
  sealCount: 288,
  verified: 41,
  witnesses: 3,
};

const homeData: HomeData = {
  counters: {
    verified: 41,
    stale: 2,
    trusted: 3,
    sealedHead: 288,
    sealedAt: "2026-09-12T04:49:44.000Z",
    witnesses: 1,
    seals: 288,
  },
  latest: [],
  domain: null,
};

/**
 * The smallest entry the page can be handed: the proof fields it prints, and
 * nothing invented. Written as the schema's own names, exactly as every other
 * suite writes a record.
 */
const entryRecord: Record<string, unknown> = {
  id: ENTRY_ID,
  schema_version: "nmk-entry-v1",
  category: "pricing",
  subject: "kestrel/kestrel-1",
  claim: "The published price of kestrel-1 is $3 per million input tokens.",
  citation: "https://docs.kestrel.example/pricing",
  evidence_tier: "stated",
  snapshot_hash: HASH,
  norm_version: "norm-v1.2",
  author: "1F916:author",
  author_operator: "k3.example",
  submitted_at: "2026-09-08T12:00:00.000Z",
  signature: "c2lnbmF0dXJl",
  approvers: [],
  reconfirmations: [],
  disputes: [],
  failure_reports: [],
  seal: null,
  staleness_window_days: 30,
  verified_at: "2026-09-08T13:00:00.000Z",
  last_confirmed: "2026-09-08",
  expires_at: "2026-10-08",
  stale: false,
  superseded_by: null,
  overturned_by: null,
  status: "verified",
  confidence: null,
};

const sidecar: Sidecar = {
  // Who met the consensus (D-138): this fixture stands for an entry decided
  // by registered operators, with no community validator and no later layer.
  verification_class: "registered",
  verification_communities: [],
  verification_single_venue: false,
  verification_binding: null,
  verification_layers: [],
  // Nobody outside has confirmed this fixture in public (D-136).
  confirmations: [],
  // No bootstrap label on this fixture (D-128): the entry it stands for
  // was not decided by one disclosed perimeter's operators.
  bootstrap: null,
  needs_replacement: false,
  effective_tier: "stated",
  test_verdict: null,
  source: {
    class: "official",
    matched_host: "docs.kestrel.example",
    authority: "kestrel",
  },
  trusted_count_at_decision: 3,
  read_share_slots: null,
  revalidations: [],
};

const entryData: EntryData = {
  entry: entryRecord,
  sidecar,
  attribution: attributionOf(entryRecord as unknown as Entry, [], new Map()),
  confidenceInputs: confidenceInputs({
    entry: entryRecord as unknown as Entry,
    sidecar,
    now: "2026-09-20T06:00:00.000Z",
  }),
  position: 12,
  events: [],
  seal: null,
  approvers: [],
  reconfirmations: [],
  superseders: [],
  stalenessWindowDays: 30,
  ledger: [],
  readShares: [],
  disputeOf: null,
  statement: null,
  disclosure: null,
};

/** Every match of a capturing pattern, in document order. */
function all(document: string, pattern: RegExp): string[] {
  return [...document.matchAll(pattern)].map((each) => each[1] ?? "");
}

function canonicals(document: string): string[] {
  return all(document, /<link rel="canonical" href="([^"]*)"/g);
}

function metas(document: string, property: string): string[] {
  return all(
    document,
    new RegExp(`<meta property="${property}" content="([^"]*)"`, "g"),
  );
}

function named(document: string, name: string): string[] {
  return all(
    document,
    new RegExp(`<meta name="${name}" content="([^"]*)"`, "g"),
  );
}

function icons(document: string): string[] {
  return all(document, /<link rel="icon" type="image\/svg\+xml" href="([^"]*)"/g);
}

function titleOf(document: string): string {
  const match = /<title>([^<]*)<\/title>/.exec(document);
  return match === null ? "" : match[1] ?? "";
}

/**
 * The whole contract, asserted the same way on every page: one of each tag, the
 * canonical built from the deployment's origin and the request's path, the card
 * agreeing with the title and the description the page already states, and no
 * script and no inline style anywhere in the document.
 */
function assertHead(document: string, path: string): void {
  expect(canonicals(document)).toEqual([`${CANONICAL_ORIGIN}${path}`]);
  expect(metas(document, "og:type")).toEqual(["website"]);
  expect(metas(document, "og:site_name")).toEqual(["nomankind"]);
  expect(metas(document, "og:title")).toEqual([titleOf(document)]);
  expect(metas(document, "og:url")).toEqual([`${CANONICAL_ORIGIN}${path}`]);
  expect(named(document, "twitter:card")).toEqual(["summary"]);
  expect(icons(document)).toEqual(["/favicon.svg"]);

  // The card's sentence is the page's own sentence, never a second one written
  // for the card: a share that described the page differently from the page
  // would be two claims about one address.
  const description = named(document, "description");
  const card = metas(document, "og:description");
  expect(card).toHaveLength(1);
  expect(card).toEqual(description.length === 0 ? [SITE_DESCRIPTION] : description);

  // No image: this repository holds no image asset, so a card naming one would
  // name a 404.
  expect(document).not.toContain("og:image");

  // The two rules the CSP enforces, held here because this suite reads whole
  // documents.
  expect(document).not.toContain("<script");
  expect(document).not.toContain(' style="');
}

describe("the head tags every page carries (D-114)", () => {
  const pages: readonly { readonly name: string; readonly path: string;
    readonly render: (ctx: PageContext) => string }[] = [
    {
      name: "the landing page",
      path: "/",
      render: (ctx) => renderLanding(ctx, landingData),
    },
    {
      name: "the home board",
      path: "/",
      render: (ctx) => renderHome(ctx, homeData),
    },
    {
      name: "an entry page",
      path: `/entries/${ENTRY_ID}`,
      render: (ctx) => renderEntry(ctx, entryData),
    },
    {
      name: "the Docs hub",
      path: "/docs",
      render: (ctx) => renderDocs(ctx),
    },
  ];

  for (const page of pages) {
    it(`states one canonical, one card and one icon on ${page.name}`, () => {
      assertHead(page.render(ctxAt(page.path)), page.path);
    });

    /**
     * A deployment that cannot say where it is canonical says nothing rather
     * than guessing: a wrong canonical points an indexer at an address that may
     * not serve this page, which is worse than leaving it to work out.
     */
    it(`omits the canonical and the og:url on ${page.name} with no origin`, () => {
      const document = page.render({
        ...ctxAt(page.path),
        canonical_origin: null,
      });
      expect(canonicals(document)).toEqual([]);
      expect(metas(document, "og:url")).toEqual([]);
      expect(metas(document, "og:type")).toEqual(["website"]);
      expect(metas(document, "og:site_name")).toEqual(["nomankind"]);
      expect(metas(document, "og:title")).toEqual([titleOf(document)]);
      expect(metas(document, "og:description")).toHaveLength(1);
      expect(named(document, "twitter:card")).toEqual(["summary"]);
      expect(icons(document)).toEqual(["/favicon.svg"]);
      expect(document).not.toContain("<script");
      expect(document).not.toContain(' style="');
    });
  }

  /**
   * The landing's title is the one place the record names itself to somebody
   * who has never heard of it, so it says what the record is and not only what
   * it is called (D-114). Pinned here as well as in the landing's own suite,
   * because the card is built from it.
   */
  it("names the record in the landing title and its card", () => {
    const document = renderLanding(landingCtx, landingData);
    expect(titleOf(document)).toBe(
      "nomankind: verified facts for models that keep learning",
    );
    expect(metas(document, "og:title")).toEqual([titleOf(document)]);
  });

  /** A page inside a section is canonical at its own path, not its section's. */
  it("builds the canonical from the request's own path", () => {
    const document = renderEntry(ctxAt(`/entries/${ENTRY_ID}`), entryData);
    expect(canonicals(document)).toEqual([
      `${CANONICAL_ORIGIN}/entries/${ENTRY_ID}`,
    ]);
  });
});

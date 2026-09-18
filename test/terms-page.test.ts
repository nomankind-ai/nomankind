/**
 * The terms of use and privacy note (D-097 item 2 as rewritten under D-127).
 *
 * Two things are being held here, and they are different. The first is that the
 * page says all of what a reader of a free record needs — the licences, the
 * absence of a warranty, the rules a caller can be refused under, and what is
 * kept about whom — and none of what it has no business saying, which is a
 * purchase term for a thing nobody sells. The second is that every number on it
 * is src/policy.ts's: the assertions below interpolate the imported constant
 * rather than retyping the value, so a cap that moves by decision moves this
 * file with it and a page that hard-coded a number would fail here.
 *
 * The page itself is pure, so most of this is a render and a string. The sitemap
 * is the exception: it is the router's answer and is asked of the router, over a
 * store with nothing in it, because what is being checked is the static list and
 * not the log.
 */

import { describe, expect, it } from "vitest";

import {
  ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE,
  ALERT_ENDPOINTS_PER_KEY,
  ALERT_TIMEOUT_MS,
  DOMAIN_SLUGS,
  excludedPartyDomains,
  FREE_READS_PER_DAY_GLOBAL,
  FREE_TIER,
  OPERATOR_READS_PER_DAY,
  RATE_TIERS,
  STANDING_ASSIGNMENT_MISSED,
  STANDING_OVERTURNED_SIGNER,
  WRITES_PER_AGENT_PER_DAY,
  WRITES_PER_AGENT_PER_DAY_PROBATION,
  WRITES_PER_AGENT_PER_DAY_SENIOR,
  WRITES_PER_CLIENT_PER_DAY,
} from "../src/policy.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import { CONTACT_EMAIL } from "../src/ui/html.js";
import { DOC_GROUPS, renderDocs } from "../src/ui/pages/docs.js";
import { renderLanding } from "../src/ui/pages/landing.js";
import { renderTerms } from "../src/ui/pages/terms.js";
import type { LandingData, PageContext } from "../src/ui/types.js";
import type { Env } from "../src/worker/env.js";
import { handlePages } from "../src/worker/pages.js";

const NOW = new Date("2026-09-18T00:00:00.000Z");

const ctx: PageContext = {
  environment: "local",
  path: "/terms",
  origin: "http://localhost:8787",
  canonical_origin: null,
};

const page = renderTerms(ctx);
/** The page with its markup whitespace collapsed, for asserting on prose. */
const flat = page.replace(/\s+/g, " ");

describe("the terms page says what a free record owes a reader", () => {
  it("heads itself as terms of use and privacy", () => {
    expect(page).toContain("<title>Terms of use and privacy · nomankind</title>");
    expect(page).toContain("<h1>Terms of use and privacy</h1>");
  });

  it("carries every section the decision asks for", () => {
    for (const heading of [
      "Free, and taking no payment",
      "The licences",
      "No warranty",
      "The caps",
      "The abuse rules",
      "What a burn costs",
      "What is stored about whom",
      "Takedown",
      "The infrastructure",
      "What the maintainer cannot do",
    ]) {
      expect([heading, page.includes(`>${heading}</h2>`)]).toEqual([
        heading,
        true,
      ]);
    }
  });

  it("says the record is free and that nothing is sold", () => {
    expect(flat).toContain("This record is free.");
    expect(flat).toContain(
      "There is no price, no invoice, no subscription and no account: nothing " +
        "on this site is bought or paid for, so nothing on this page is about a " +
        "transaction.",
    );
    expect(flat).toContain(
      "Nothing in this system collects or moves a payment, and no door puts a price on anything.",
    );
    // D-127: training on the data is free, and there is no second licence for it.
    expect(flat).toContain("Training a model on this record is free");
    expect(flat).toContain(
      "There are no billing records and no terms of a transaction, because nothing here is bought.",
    );
  });

  it("names both licences and keeps the snapshots out of CC0", () => {
    expect(page).toContain(
      "https://creativecommons.org/publicdomain/zero/1.0/",
    );
    expect(page).toContain(
      "https://github.com/nomankind-ai/nomankind/blob/main/LICENSE",
    );
    expect(flat).toContain("under <a");
    expect(flat).toContain(">CC0</a > from the seal that covers it");
    expect(flat).toContain(">Apache-2.0</a >");
    expect(flat).toContain("Snapshots are not CC0 and cannot be");
  });

  it("warrants nothing, and says the remedy is a dispute", () => {
    expect(flat).toContain(
      "The record publishes what its validators signed and what its verifier can recompute, as is.",
    );
    expect(flat).toContain("It does not warrant that an entry is true");
    expect(flat).toContain(
      "The remedy for a wrong entry is a dispute, which anyone with standing can file against it",
    );
    expect(flat).toContain(
      "An entry a dispute overturns is not deleted and not quietly edited: it stays where it is, marked overturned",
    );
  });
});

describe("every number on it is published policy", () => {
  /** One named row of a numbers table, exactly as the page writes it. */
  function row(name: string, value: number): string {
    return (
      `<td class="mono">${name}</td> <td class="mono">${value}</td>`
    );
  }

  it("prints each cap under the constant's own name", () => {
    const caps: readonly (readonly [string, number])[] = [
      [`RATE_TIERS.${FREE_TIER}.reads_per_day`, RATE_TIERS[FREE_TIER]!.reads_per_day],
      ["FREE_READS_PER_DAY_GLOBAL", FREE_READS_PER_DAY_GLOBAL],
      ["RATE_TIERS.standard.reads_per_day", RATE_TIERS["standard"]!.reads_per_day],
      ["RATE_TIERS.high.reads_per_day", RATE_TIERS["high"]!.reads_per_day],
      ["OPERATOR_READS_PER_DAY", OPERATOR_READS_PER_DAY],
      ["WRITES_PER_AGENT_PER_DAY", WRITES_PER_AGENT_PER_DAY],
      ["WRITES_PER_AGENT_PER_DAY_PROBATION", WRITES_PER_AGENT_PER_DAY_PROBATION],
      ["WRITES_PER_AGENT_PER_DAY_SENIOR", WRITES_PER_AGENT_PER_DAY_SENIOR],
      ["WRITES_PER_CLIENT_PER_DAY", WRITES_PER_CLIENT_PER_DAY],
      ["ALERT_ENDPOINTS_PER_KEY", ALERT_ENDPOINTS_PER_KEY],
      ["ALERT_TIMEOUT_MS", ALERT_TIMEOUT_MS],
      ["ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE", ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE],
    ];
    for (const [name, value] of caps) {
      expect([name, flat.includes(row(name, value))]).toEqual([name, true]);
    }
  });

  it("prints the two burns under the formula's own names", () => {
    expect(flat).toContain(
      row("STANDING_OVERTURNED_SIGNER", STANDING_OVERTURNED_SIGNER),
    );
    expect(flat).toContain(
      row("STANDING_ASSIGNMENT_MISSED", STANDING_ASSIGNMENT_MISSED),
    );
    // And in the prose too, from the same constants.
    expect(flat).toContain(
      `burns ${STANDING_OVERTURNED_SIGNER} standing from every operator that signed it`,
    );
    expect(flat).toContain(`burns ${STANDING_ASSIGNMENT_MISSED}`);
  });

  it("counts each domain's excluded parties off the registry", () => {
    expect(DOMAIN_SLUGS.length).toBeGreaterThan(0);
    for (const slug of DOMAIN_SLUGS) {
      expect([
        slug,
        flat.includes(
          `<span class="mono">${slug}</span> (${excludedPartyDomains(slug).length})`,
        ),
      ]).toEqual([slug, true]);
    }
  });

  it("states the alert rules with the alert numbers", () => {
    expect(flat).toContain(
      `A change-alert delivery is given ${ALERT_TIMEOUT_MS} ms; after ` +
        `${ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE} consecutive timed-out deliveries ` +
        "the endpoint is disabled rather than retried forever.",
    );
    expect(flat).toContain(
      `It keeps its place among the ${ALERT_ENDPOINTS_PER_KEY} a key may hold`,
    );
  });
});

describe("what is stored about whom", () => {
  it("names each party and what is kept", () => {
    for (const who of [
      "A reader with no key",
      "A holder of a free key",
      "A domain operator",
      "A community operator",
      "An alert subscriber",
    ]) {
      expect([who, flat.includes(`<td>${who}</td>`)]).toEqual([who, true]);
    }
  });

  it("keeps a keyless reader to a hashed scope and nothing else", () => {
    expect(flat).toContain(
      "The SHA-256 of the client address, as the scope the day's read counter is kept under, and nothing else.",
    );
    expect(flat).toContain(
      "the counter records how much was read under that scope and never what was read",
    );
  });

  it("never stores a key's secret, only its digest", () => {
    expect(flat).toContain("the SHA-256 of its secret");
    expect(flat).toContain(
      "The secret itself is shown once at the door and never stored",
    );
  });

  it("says an operator's record is public by its own signing", () => {
    expect(flat).toContain("all of it is public by the operator's own signing");
    expect(flat).toContain(
      "the capture of that profile exactly as the venue served it",
    );
  });

  it("says the alert secret is wrapped at rest only conditionally", () => {
    // A1's work, and the page may only claim it in the form the deployment can
    // actually be in: a deployment without the variable holds the secret in the
    // clear, and an unconditional sentence here would be the page promising a
    // property of somebody else's environment.
    expect(flat).toContain(
      'The secret is wrapped at rest once <span class="mono">ALERT_SIGNING_KEY</span> is set on the deployment.',
    );
    expect(flat).not.toContain("secrets are wrapped at rest.");
  });
});

describe("the posture the paper sets out", () => {
  it("offers the takedown address and keeps the proof", () => {
    expect(flat).toContain(
      `<a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>`,
    );
    expect(flat).toContain(
      "What cannot be withdrawn is the hash of that capture, the signatures over it, or the sealed record",
    );
    expect(flat).toContain(
      "a withdrawn capture is visibly a withdrawn capture and never a quietly changed one",
    );
  });

  it("puts the transport under Cloudflare's own terms", () => {
    expect(page).toContain("https://www.cloudflare.com/terms/");
    expect(flat).toContain(
      "cover the transport: the connection, the edge, the abuse handling at the network layer",
    );
  });

  it("names the maintainer's limits and the fork as the check", () => {
    expect(flat).toContain(
      "It cannot approve an entry, cannot edit one, and cannot validate",
    );
    expect(flat).toContain("it sets no price, because nothing in this record has one");
    expect(flat).toContain(
      "it is advisory while the maintainer still hosts the record",
    );
    expect(flat).toContain("The check on the maintainer is not the vote. It is the fork.");
  });

  it("links the policy page, the paper and the fork guide", () => {
    expect(page).toContain(`<a href="/policy">published policy</a>`);
    expect(page).toContain(`<a href="/docs/whitepaper">the whitepaper</a>`);
    expect(page).toContain(`<a href="/docs/fork">the fork guide</a>`);
  });

  it("carries no script and no inline style", () => {
    expect(page).not.toContain("<script");
    expect(page).not.toContain(' style="');
    expect(page).not.toContain(" onclick=");
  });
});

describe("the page is reachable", () => {
  it("is one card of the docs hub, under Read the record", () => {
    const first = DOC_GROUPS[0]!;
    expect(first.title).toBe("Read the record");
    expect(first.cards.map((each) => each.href)).toContain("/terms");
    const docs = renderDocs({ ...ctx, path: "/docs" }).replace(/\s+/g, " ");
    expect(docs).toContain(
      `<a class="step" href="/terms" ><span class="step-t">Terms</span>`,
    );
  });

  it("is linked once from the app footer", () => {
    const footer = page.slice(page.indexOf("<footer"));
    expect(footer).toContain(`<a href="/terms">Terms</a>`);
    expect(footer.split(`<a href="/terms">`)).toHaveLength(2);
    // Ours and internal: no new tab, no nofollow, exactly as Mirror is.
    expect(page).not.toContain(`<a href="/terms" target="_blank"`);
    expect(footer.indexOf("Whitepaper")).toBeLessThan(footer.indexOf(">Terms<"));
    expect(footer.indexOf(">Terms<")).toBeLessThan(footer.indexOf(">Contact<"));
  });

  it("is linked once from the landing footer", () => {
    const data: LandingData = {
      seals: [],
      sealCount: 0,
      verified: 0,
      witnesses: 0,
    };
    const landing = renderLanding({ ...ctx, path: "/" }, data);
    const footer = landing.slice(landing.indexOf(`<footer class="landing-footer`));
    expect(footer).toContain(`<a href="/terms">TERMS</a>`);
    expect(footer.split(`<a href="/terms">`)).toHaveLength(2);
    // The top bar is unchanged: the mailto is still its last anchor.
    const nav = landing.slice(
      landing.indexOf(`<nav class="topnav">`),
      landing.indexOf("</nav>"),
    );
    expect(nav).not.toContain(`href="/terms"`);
  });

  it("is listed in the sitemap", async () => {
    const response = await handlePages(
      new Request("https://app.example/sitemap.xml"),
      emptyEnv(),
      { now: NOW },
    );
    expect(response).not.toBeNull();
    expect(response!.status).toBe(200);
    const xml = await response!.text();
    expect(xml).toContain("<loc>https://app.example/terms</loc>");
  });

  it("answers HTML on its own route", async () => {
    const response = await handlePages(
      new Request("https://app.example/terms", {
        headers: { accept: "text/html" },
      }),
      emptyEnv(),
      { now: NOW },
    );
    expect(response).not.toBeNull();
    expect(response!.status).toBe(200);
    expect(response!.headers.get("content-type")).toBe(
      "text/html; charset=utf-8",
    );
    expect(await response!.text()).toContain(
      "<h1>Terms of use and privacy</h1>",
    );
  });

  it("refuses a method it does not answer with an Allow header", async () => {
    const response = await handlePages(
      new Request("https://app.example/terms", { method: "PUT" }),
      emptyEnv(),
      { now: NOW },
    );
    expect(response).not.toBeNull();
    expect(response!.status).toBe(405);
    expect(response!.headers.get("allow")).toBe("GET, HEAD");
  });
});

/**
 * A store with nothing in it.
 *
 * The sitemap's static list is what is being checked, and an empty log is the
 * cleanest way to see it: every `<loc>` in the document is then a page rather
 * than an entry or an operator. The page route itself reads nothing at all.
 */
function emptyEnv(): Env {
  const statement = {
    bind: () => statement,
    first: () => Promise.resolve(null),
    all: () => Promise.resolve({ results: [], success: true }),
    run: () => Promise.resolve({ results: [], success: true }),
  } as unknown as D1LikeStatement;
  const db: D1Like = {
    prepare: () => statement,
    batch: () => Promise.resolve([]),
    exec: () => Promise.resolve({ count: 0, duration: 0 }),
  };
  return {
    DB: db,
    CAPTURES: {},
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  } as unknown as Env;
}

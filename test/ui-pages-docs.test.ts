/**
 * The four pages that document the system rather than the log: policy, API,
 * genesis, and the apex landing page.
 *
 * These pages are the ones a reader checks the code against, so the tests hold
 * them to the code rather than to a screenshot. The policy page has to name
 * every key of POLICY — the whole object, enumerated, so a number added by a
 * later decision cannot go unpublished — and print the values it reads rather
 * than any of its own. The API page has to name every endpoint that exists and
 * the authentication rule in the order the verifier applies it. The genesis page
 * has to show the attestation verbatim, because a paraphrase of a signed string
 * is not the signed string. And the landing page has to be a document that
 * survives the content-security-policy: no script anywhere, and not one inline
 * style attribute, because the CSP would drop both and a page whose look depends
 * on what the browser refused is a page nobody sees.
 */

import { describe, expect, it } from "vitest";
import {
  LIST_PAGE_LIMIT,
  POLICY,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
} from "../src/policy.js";
import {
  ATTESTATION_TEXT,
  ATTESTATION_VERSION,
  TXT_RECORD_PREFIX,
} from "../src/registry.js";
import { renderApi } from "../src/ui/pages/api.js";
import { renderGenesis } from "../src/ui/pages/genesis.js";
import { LANDING_CSS, renderLanding } from "../src/ui/pages/landing.js";
import { renderPolicy } from "../src/ui/pages/policy.js";
import type { GenesisData, PageContext } from "../src/ui/types.js";

const ctx: PageContext = {
  environment: "demo",
  path: "/policy",
  origin: "https://demo.nomankind.ai",
};

describe("renderPolicy", () => {
  const page = renderPolicy(ctx, POLICY);

  it("names every key of POLICY, so a number added later cannot hide", () => {
    for (const key of Object.keys(POLICY)) {
      expect(page, `POLICY key ${key} is not on the policy page`).toContain(key);
    }
  });

  it("prints the values it read rather than values of its own", () => {
    expect(page).toContain(String(POLICY.TRUSTED_POOL_SWITCH));
    expect(page).toContain(String(POLICY.ASSIGNMENT_WINDOW_HOURS));
    expect(page).toContain(POLICY.NORM_VERSION);
  });

  it("gives every staleness category a row, window or no window", () => {
    for (const [category, days] of Object.entries(
      POLICY.STALENESS_WINDOW_DAYS,
    )) {
      expect(page).toContain(`STALENESS_WINDOW_DAYS.${category}`);
      if (days === null) {
        expect(page).toContain("no window (event category)");
      } else {
        expect(page).toContain(`${days} days`);
      }
    }
  });

  it("names every pinned witness by operator", () => {
    for (const pin of POLICY.WITNESS_PIN) {
      expect(page).toContain(pin.operator);
      expect(page).toContain(pin.public_key);
    }
  });

  it("says plainly that there is no seed fee (D-052)", () => {
    expect(page).toContain(
      "There is no seed fee: contributors are paid only from read revenue",
    );
    expect(page).toContain("D-052");
  });

  it("marks the numbers the paper names and nothing publishes yet", () => {
    expect(page).toContain("not yet published (M21)");
    expect(page).toContain("not yet published (M24)");
  });

  it("points at the JSON the kernel serves from the same module", () => {
    expect(page).toContain(`href="/policy"`);
    expect(page).toContain("Accept: application/json");
  });

  it("carries no script", () => {
    expect(page).not.toContain("<script");
  });
});

describe("renderApi", () => {
  const page = renderApi(ctx);

  it("documents every endpoint that exists", () => {
    const paths = [
      "/health",
      "/operators",
      "/genesis",
      "/entries",
      "/captures/",
      "/events",
      "/seals",
      "/anchors",
      "/read",
      "/sync",
      "/policy",
    ];
    for (const path of paths) {
      expect(page, `${path} is not documented`).toContain(path);
    }
  });

  it("names the four headers a signed write carries", () => {
    for (const header of [
      "x-nomankind-agent",
      "x-nomankind-timestamp",
      "x-nomankind-nonce",
      "x-nomankind-signature",
    ]) {
      expect(page).toContain(header);
    }
  });

  it("lists the six authentication failures in the order they are checked", () => {
    const reasons = [
      "missing_header",
      "agent_mismatch",
      "bad_timestamp",
      "clock_skew",
      "replay",
      "bad_signature",
    ];
    const positions = reasons.map((reason) =>
      page.indexOf(`>${reason}</span>`),
    );
    for (const [index, at] of positions.entries()) {
      expect(at, `${reasons[index]} is not in the rule block`).toBeGreaterThan(
        -1,
      );
      if (index > 0) {
        expect(at).toBeGreaterThan(positions[index - 1] as number);
      }
    }
  });

  it("names the signing tag and the key command", () => {
    expect(page).toContain("nomankind-request-v1");
    expect(page).toContain("npm run keygen");
  });

  it("spells the example commands against this origin", () => {
    expect(page).toContain(ctx.origin);
  });

  it("names what is not built yet with its milestone", () => {
    expect(page).toContain("M20");
    expect(page).toContain("M23");
    expect(page).toContain("M24");
  });

  it("takes every paging bound from the policy module, never its own number", () => {
    // The page documents the bound the routes actually enforce, so a limit
    // changed in src/policy.ts changes the documentation with it.
    expect(page).toContain(`limit=&lt;1..${LIST_PAGE_LIMIT}&gt;`);
    expect(page).toContain(`--limit ${LIST_PAGE_LIMIT}`);

    // And no other bound anywhere: a second number on the page would be a
    // second source of truth, and one of the two would be wrong.
    const bounds = [...page.matchAll(/1\.\.(\d+)/g)].map((each) =>
      Number(each[1]),
    );
    expect(bounds.length).toBeGreaterThan(0);
    expect([...new Set(bounds)]).toEqual([LIST_PAGE_LIMIT]);
  });

  it("carries no script", () => {
    expect(page).not.toContain("<script");
  });
});

const rows: GenesisData["rows"] = [
  {
    operator: "northgate.example",
    registeredSeq: 12,
    trustedSeq: 19,
    validations: 4,
    lastValidationAt: "2026-09-08T11:02:00Z",
  },
  {
    operator: "cindermill.example",
    registeredSeq: 14,
    trustedSeq: null,
    validations: 0,
    lastValidationAt: null,
  },
];

function genesisData(overrides: Partial<GenesisData> = {}): GenesisData {
  return {
    rows,
    attestationText: ATTESTATION_TEXT,
    attestationVersion: ATTESTATION_VERSION,
    txtRecordPrefix: TXT_RECORD_PREFIX,
    maintainerConfigured: false,
    ...overrides,
  };
}

describe("renderGenesis", () => {
  const page = renderGenesis(ctx, genesisData());

  it("shows the attestation verbatim, not a paraphrase of it", () => {
    expect(page).toContain(ATTESTATION_TEXT);
    expect(page).toContain(ATTESTATION_VERSION);
  });

  it("gives the TXT record name in full", () => {
    expect(page).toContain(`${TXT_RECORD_PREFIX}.&lt;domain&gt;`);
  });

  it("takes the outside-operator threshold from the policy module", () => {
    expect(page).toContain(
      `${VERIFICATION_MIN_OUTSIDE_OPERATORS} verified operators outside the`,
    );
    expect(page).not.toContain("three verified operators");
  });

  it("names all three joining steps", () => {
    expect(page).toContain("Prove a domain");
    expect(page).toContain("Complete payout onboarding");
    expect(page).toContain("Sign the independence attestation");
    expect(page).toContain("mock-verified-");
  });

  it("shows the register body and points at the API page", () => {
    expect(page).toContain("POST /operators");
    expect(page).toContain(`href="/api"`);
  });

  it("shows every row the log holds", () => {
    for (const row of rows) {
      expect(page).toContain(row.operator);
      expect(page).toContain(`>${row.registeredSeq}<`);
    }
    expect(page).toContain("not named");
  });

  it("says so when nothing has registered here", () => {
    const empty = renderGenesis(ctx, genesisData({ rows: [] }));
    expect(empty).toContain("No operators registered on this environment.");
  });

  it("says whether genesis naming is configured on this environment", () => {
    expect(page).toContain("not configured until production go-live (M25)");
    const configured = renderGenesis(
      ctx,
      genesisData({ maintainerConfigured: true }),
    );
    expect(configured).toContain(
      "maintainer key is set on this environment",
    );
  });

  it("renders the issue placeholder as plain text and never as a link", () => {
    const placeholder =
      "[ISSUE LINK: the genesis call is opened in the repository at production go-live, M25]";
    expect(page).toContain(placeholder);
    const at = page.indexOf(placeholder);
    // Nothing between the placeholder and the tag that opens it may be an
    // anchor: a link to a page that does not exist is a promise the log cannot
    // keep.
    const before = page.slice(0, at);
    expect(before.lastIndexOf("<a")).toBeLessThan(before.lastIndexOf("</a>"));
    expect(page.slice(at + placeholder.length, at + placeholder.length + 4)).toBe(
      "</p>",
    );
  });

  it("carries no script", () => {
    expect(page).not.toContain("<script");
  });
});

describe("renderLanding", () => {
  const page = renderLanding(ctx);

  it("is a whole document of its own with the landing stylesheet", () => {
    expect(page.startsWith("<!doctype html>")).toBe(true);
    expect(page).toContain(`<html lang="en">`);
    expect(page).toContain("<title>nomankind</title>");
    expect(page).toContain(`href="/static/landing.css"`);
    expect(page).toContain("fonts.googleapis.com");
  });

  it("leads with the hero line", () => {
    expect(page).toContain("Proof first. Use second.");
  });

  it("holds the five values", () => {
    expect(page).toContain("Owned by no lab.");
    expect(page).toContain("Facts, never opinions.");
    expect(page).toContain("Rewards for being right, never for being busy.");
    expect(page).toContain("Checkable by anyone, offline.");
    expect(page).toContain("Exit is the only real check.");
  });

  it("offers both doors", () => {
    expect(page).toContain(`href="https://app.nomankind.ai"`);
    expect(page).toContain(`href="https://demo.nomankind.ai"`);
    expect(page).toContain("Open the app");
    expect(page).toContain("Try the demo");
  });

  it("links the paper, the code, the mirror and the registry", () => {
    expect(page).toContain(
      "https://github.com/nomankind-ai/nomankind/blob/main/paper/WHITEPAPER.md",
    );
    expect(page).toContain(`href="https://github.com/nomankind-ai/log"`);
    expect(page).toContain(`href="https://1f916.org"`);
  });

  it("closes on the two tiers and the licence line only", () => {
    expect(page).toContain("Provenance is the floor.");
    expect(page).toContain("CODE APACHE-2.0 · DATA CC0");
  });

  it("survives the content-security-policy: no script, no inline style", () => {
    expect(page).not.toContain("<script");
    expect(page).not.toContain("style=");
  });
});

describe("LANDING_CSS", () => {
  it("is the landing page's whole look, in one string", () => {
    expect(LANDING_CSS.length).toBeGreaterThan(0);
    expect(LANDING_CSS).toContain("Instrument Serif");
    expect(LANDING_CSS).toContain("Manrope");
    expect(LANDING_CSS).toContain("JetBrains Mono");
  });

  it("stops every motion under prefers-reduced-motion", () => {
    expect(LANDING_CSS).toContain("prefers-reduced-motion");
  });

  it("reveals on scroll only where the browser has a view timeline", () => {
    expect(LANDING_CSS).toContain("@supports (animation-timeline: view())");
  });

  it("answers under 700 px", () => {
    expect(LANDING_CSS).toContain("@media (max-width: 700px)");
  });
});

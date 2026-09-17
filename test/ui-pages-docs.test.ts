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

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { HASH_TAG_ALERT } from "../src/alerts.js";
import { ANSWER_REFUSALS, SCORE_REFUSALS } from "../src/attest.js";
import { CORE_KEYS } from "../src/core.js";
import {
  ASSIGNMENT_WINDOW_HOURS,
  DEFAULT_DOMAIN,
  DOMAINS,
  DOMAIN_SLUGS,
  LIST_PAGE_LIMIT,
  POLICY,
  SCHEMA_VERSION,
  SEAL_INTERVAL_MINUTES,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
  attestationFor,
  domainPolicy,
  excludedPartyDomains,
  stalenessWindowDays,
} from "../src/policy.js";
import {
  ATTESTATION_TEXT,
  ATTESTATION_VERSION,
  JOIN_REFUSALS,
  TXT_RECORD_PREFIX,
} from "../src/registry.js";
import { READ_QUERY_REFUSALS } from "../src/read.js";
import { STAGE_COUNT } from "../src/status.js";
import { SUBMISSION_REFUSALS } from "../src/submit.js";
import { SYNC_QUERY_REFUSALS } from "../src/sync.js";
import { renderApi } from "../src/ui/pages/api.js";
import { DOMAIN_COPY, renderDomains } from "../src/ui/pages/domains.js";
import { renderDryRun } from "../src/ui/pages/dry-run.js";
import { VALIDATION_REFUSALS } from "../src/validate.js";
import { renderGenesis } from "../src/ui/pages/genesis.js";
import { renderHowItWorks } from "../src/ui/pages/how-it-works.js";
import {
  APEX_URL,
  CONTACT_EMAIL,
  escapeHtml,
  shortHash,
} from "../src/ui/html.js";
import {
  LANDING_CSS,
  LANDING_CSS_HREF,
  renderLanding,
} from "../src/ui/pages/landing.js";
import { renderPolicy } from "../src/ui/pages/policy.js";
import { DOC_GROUPS, renderDocs } from "../src/ui/pages/docs.js";
import {
  FORK_DOCUMENT,
  SUMMARY_DOCUMENT,
  WHITEPAPER_DOCUMENT,
  WHITEPAPER_VERSION,
  renderDocument,
} from "../src/ui/pages/document.js";
import { headings, sections } from "../src/ui/markdown.js";
import type {
  DomainsData,
  GenesisData,
  HowItWorksData,
  LandingData,
  PageContext,
} from "../src/ui/types.js";

const ctx: PageContext = {
  environment: "demo",
  path: "/policy",
  origin: "https://demo.nomankind.ai",
  canonical_origin: "https://demo.nomankind.ai",
};

/** One count per registered domain, for the tests that only need the page. */
const DOMAINS_READING: DomainsData = {
  counts: Object.fromEntries(
    DOMAIN_SLUGS.map((slug) => [slug, { entries: 4, trustedOperators: 3 }]),
  ),
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

  it("gives every registered domain its own group, read from POLICY", () => {
    // Nothing category-shaped is global any more (decision D-071): a window, a
    // transcript rule and an excluded party belong to a domain, and the page
    // publishes them under the path they actually live at.
    for (const [slug, domain] of Object.entries(POLICY.DOMAINS)) {
      const path = `DOMAINS.${slug}`;
      expect(page, `${slug} has no group`).toContain(`Domains · ${slug}`);
      expect(page).toContain(`<td class="mono">${path}.name</td>`);
      expect(page).toContain(`<td class="mono">${domain.name}</td>`);
      expect(page).toContain(`<td class="mono">${path}.categories</td>`);
      expect(page).toContain(
        `<td class="mono">${domain.categories.join(", ")}</td>`,
      );
      expect(page).toContain(
        `<td class="mono">${path}.transcript_categories</td>`,
      );
      expect(page).toContain(
        `<td class="mono">${domain.transcript_categories.join(", ")}</td>`,
      );
      expect(page).toContain(
        `<td class="mono">${path}.excluded_parties.rule</td>`,
      );
      expect(page).toContain(`<td class="mono">${domain.excluded_parties.rule}</td>`);
      expect(page).toContain(
        `<td class="mono">${path}.attestation.version</td>`,
      );
      expect(page).toContain(
        `<td class="mono">${domain.attestation.version}</td>`,
      );
      expect(page).toContain(`<td class="mono">${path}.subject_convention</td>`);

      // Every window of every category the domain admits, named by its path.
      for (const category of domain.categories) {
        const days = domain.staleness_window_days[category];
        expect(page, `${path}.${category} has no window row`).toContain(
          `<td class="mono">${path}.staleness_window_days.${category}</td>`,
        );
        expect(page).toContain(
          days === null
            ? `<td class="mono">no window (event category)</td>`
            : `<td class="mono">${days} days</td>`,
        );
      }

      // The three fields D-096 added, each published where it lives: the
      // per-entry half of the exclusion rule on every domain, and the two
      // optional rules only on the domains that publish them. A domain without
      // one gets no row at all, because "none" would be a rule nobody set.
      expect(page).toContain(
        `<td class="mono">${path}.excluded_parties.subject_authority</td>`,
      );
      const disclosure = domain.disclosure;
      if (disclosure === undefined) {
        expect(page).not.toContain(`${path}.disclosure.categories`);
        expect(page).not.toContain(`${path}.disclosure.window_days`);
      } else {
        expect(page).toContain(`<td class="mono">${path}.disclosure.categories</td>`);
        expect(page).toContain(
          `<td class="mono">${disclosure.categories.join(", ")}</td>`,
        );
        expect(page).toContain(
          `<td class="mono">${path}.disclosure.window_days</td>`,
        );
        expect(page).toContain(
          `<td class="mono">${disclosure.window_days} days</td>`,
        );
      }
      const versions = domain.version_staleness;
      if (versions === undefined) {
        expect(page).not.toContain(`${path}.version_staleness.categories`);
      } else {
        expect(page).toContain(
          `<td class="mono">${path}.version_staleness.categories</td>`,
        );
        expect(page).toContain(
          `<td class="mono">${versions.categories.join(", ")}</td>`,
        );
      }

      // And the excluded parties themselves, one row each, in order.
      domain.excluded_parties.domains.forEach((party, index) => {
        expect(page, `${party} is not published`).toContain(
          `<td class="mono">${path}.excluded_parties.domains[${index}]</td>`,
        );
        expect(page).toContain(`<td class="mono">${party}</td>`);
      });
    }
  });

  it("publishes every domain's source policy, all three tables, from POLICY", () => {
    // Decision D-080. The gate, the authority table and the recognized list are
    // published under the path they live at, and every value is read off the
    // frozen object: a host typed into the page would be a second place the
    // policy lives, which is the one thing this page exists to prevent.
    for (const [slug, domain] of Object.entries(POLICY.DOMAINS)) {
      const path = `DOMAINS.${slug}.sources`;
      expect(page, `${slug} has no sources panel`).toContain(
        `Domains · ${slug} · sources`,
      );
      expect(page).toContain(`<td class="mono">${path}.official_required</td>`);
      expect(page).toContain(
        `<td class="mono">${domain.sources.official_required.join(", ")}</td>`,
      );

      for (const [authority, row] of Object.entries(domain.sources.authorities)) {
        const label = row.fixture === true ? `${authority} (fixture)` : authority;
        expect(page, `${authority} has no row`).toContain(label);
        expect(page, `${authority} does not publish its hosts`).toContain(
          `<td class="mono">${row.hosts.join(", ")}</td>`,
        );
      }

      domain.sources.recognized_hosts.forEach((host, index) => {
        expect(page, `${host} is not published`).toContain(
          `<td class="mono">${path}.recognized_hosts[${index}]</td>`,
        );
        expect(page).toContain(`<td class="mono">${host}</td>`);
      });
    }
  });

  it("says what the source policy does not automate", () => {
    // The tables say whose page may be cited; three operators still say whether
    // the page cited actually supports the claim. A page that published the
    // tables without that sentence would read as if a hostname were the check.
    expect(page).toContain(
      "A validator's approval asserts that the cited page supports the claim.",
    );
    // And the host rule itself, exactly, including the subdomain trap.
    expect(page).toContain("anthropic.com.evil.tld");
    expect(page).toContain("source_not_official");
    expect(page).toContain("unknown_authority");
  });

  it("publishes the two status thresholds as their own group", () => {
    // The status page's whole judgement is these two numbers, so they are
    // published beside every other number the record runs on rather than left in
    // the code that reads them.
    expect(page).toContain("Status");
    expect(page).toContain(
      `<td class="mono">STATUS_ATTENTION_AFTER_INTERVALS</td>`,
    );
    expect(page).toContain(
      `<td class="mono">${POLICY.STATUS_ATTENTION_AFTER_INTERVALS} intervals</td>`,
    );
    expect(page).toContain(`<td class="mono">STATUS_FAILING_AFTER_MINUTES</td>`);
    expect(page).toContain(
      `<td class="mono">${POLICY.STATUS_FAILING_AFTER_MINUTES} minutes</td>`,
    );
  });

  it("no longer names the globals a domain replaced", () => {
    // The three names left src/policy.ts and src/evidence.ts, so a page still
    // publishing one would be publishing a table that no longer exists.
    expect(page).not.toContain("STALENESS_WINDOW_DAYS");
    expect(page).not.toContain("MODEL_PROVIDER_DOMAINS");
    expect(page).not.toContain("TRANSCRIPT_CATEGORIES");
  });

  it("publishes the schema version beside the normalization version", () => {
    expect(page).toContain(`<td class="mono">SCHEMA_VERSION</td>`);
    expect(page).toContain(`<td class="mono">${POLICY.SCHEMA_VERSION}</td>`);
    expect(page).toContain(`<td class="mono">NORM_VERSION</td>`);
    expect(page).toContain(`<td class="mono">${POLICY.NORM_VERSION}</td>`);
  });

  it("names every pinned witness by operator", () => {
    for (const pin of POLICY.WITNESS_PIN) {
      expect(page).toContain(pin.operator);
      expect(page).toContain(pin.public_key);
    }
  });

  it("says plainly that the record is free and nothing is staked in money", () => {
    // Decision D-127. The seed-fee note and the read-revenue promise beside it
    // went with the money they were about: what a contributor earns is standing,
    // and a stake is contribution rather than a payment.
    expect(page).toContain("The record is free (decision D-127).");
    expect(page).toContain("no read-share slot and no fee");
    expect(page).toContain("staked in money");
    expect(page).not.toContain("seed fee");
    expect(page).not.toContain("read revenue");
  });

  it("groups access and alerts, and reads every one of its numbers from POLICY", () => {
    // The tiers and the alert numbers, each read off the frozen object: a page
    // that held any of them itself would be a second place a published number
    // lives. No provider strings any more — there is no provider (D-127).
    expect(page).toContain(">Access and alerts</h2>");
    expect(page).not.toContain("STRIPE");

    for (const [slug, tier] of Object.entries(POLICY.RATE_TIERS)) {
      expect(page, `RATE_TIERS.${slug} has no row`).toContain(
        `<td class="mono">RATE_TIERS.${slug}</td>`,
      );
      expect(page).toContain(
        `${tier.name} · ${tier.reads_per_day} reads per day · ${
          tier.key ? "key" : "no key"
        }`,
      );
    }

    for (const [name, value] of [
      ["FREE_TIER", POLICY.FREE_TIER],
      [
        "FREE_READS_PER_DAY_GLOBAL",
        `${POLICY.FREE_READS_PER_DAY_GLOBAL} reads per day`,
      ],
      [
        "OPERATOR_READS_PER_DAY",
        `${POLICY.OPERATOR_READS_PER_DAY} reads per day`,
      ],
      ["ALERT_ENDPOINTS_PER_KEY", String(POLICY.ALERT_ENDPOINTS_PER_KEY)],
      ["ALERT_TIMEOUT_MS", `${POLICY.ALERT_TIMEOUT_MS} ms`],
      ["ALERT_RETRY_MINUTES", POLICY.ALERT_RETRY_MINUTES.join(", ")],
      ["ALERT_KINDS", POLICY.ALERT_KINDS.join(", ")],
    ] as const) {
      expect(page, `${name} has no row`).toContain(
        `<td class="mono">${name}</td>`,
      );
      expect(page, `${name} does not show its value`).toContain(
        `<td class="mono">${value}</td>`,
      );
    }
  });

  it("publishes the release window as a Release group, from POLICY", () => {
    // Decision D-127 put the record's release where the money group used to be,
    // and the number is rendered rather than spelled: a fork that sets a window
    // of its own gets a page that says so instead of a word that would lie.
    expect(page).toContain(">Release</h2>");
    expect(page).toContain(`<td class="mono">RELEASE_WINDOW_DAYS</td>`);
    expect(page).toContain(
      `<td class="mono">${POLICY.RELEASE_WINDOW_DAYS} days</td>`,
    );
    expect(page).toContain("released the moment it is sealed");
    expect(page).not.toContain(">Money and standing</h2>");
    for (const gone of [
      "READ_SHARE_SPLIT",
      "SLOT_COUNT",
      "READ_PRICE_MICROS_PER_READ",
      "CONTRIBUTOR_SHARE_PERCENT",
      "CONTRIBUTOR_SHARE_FLOOR_PERCENT",
      "PAYOUT_MINIMUM_MICROS",
      "PAYOUT_CYCLE",
    ]) {
      expect([gone, page.includes(`<td class="mono">${gone}</td>`)]).toEqual([
        gone,
        false,
      ]);
    }
  });

  it("has no placeholder left: every number the paper names is published", () => {
    // M21 published the standing formula, the price, the payout minimum and the
    // cycle; M24 published the tiers, the rate limits and the alert numbers, so
    // the last placeholder row is gone. A row saying a number is unpublished
    // while the code holds one would be the page disagreeing with the module it
    // is read from, which is the one thing it exists to prevent.
    expect(page).not.toContain("not yet published");
  });

  it("publishes the standing formula, every term of it, read from POLICY", () => {
    expect(page).toContain(">Standing</h2>");
    for (const [name, value] of [
      [
        "STANDING_VALIDATION_VOLUNTEERED",
        `${POLICY.STANDING_VALIDATION_VOLUNTEERED} standing`,
      ],
      [
        "STANDING_VALIDATION_ASSIGNED",
        `${POLICY.STANDING_VALIDATION_ASSIGNED} standing`,
      ],
      // D-087: the standing side of "the operators who measure are paid more".
      [
        "STANDING_VALIDATION_REPRODUCED",
        `${POLICY.STANDING_VALIDATION_REPRODUCED} standing`,
      ],
      [
        "STANDING_SUBMISSION_VERIFIED",
        `${POLICY.STANDING_SUBMISSION_VERIFIED} standing`,
      ],
      ["STANDING_DISPUTE_UPHELD", `${POLICY.STANDING_DISPUTE_UPHELD} standing`],
      // D-095: the reward on a check that found the fact changed, in standing.
      [
        "STANDING_REVALIDATION_CHANGED",
        `${POLICY.STANDING_REVALIDATION_CHANGED} standing`,
      ],
      [
        "STANDING_OVERTURNED_SIGNER",
        `${POLICY.STANDING_OVERTURNED_SIGNER} standing`,
      ],
      [
        "STANDING_ASSIGNMENT_MISSED",
        `${POLICY.STANDING_ASSIGNMENT_MISSED} standing`,
      ],
      ["STANDING_TRUSTED_ENTRY", `${POLICY.STANDING_TRUSTED_ENTRY} standing`],
      ["STANDING_TRUSTED_STAY", `${POLICY.STANDING_TRUSTED_STAY} standing`],
    ] as const) {
      expect(page, `${name} has no row`).toContain(
        `<td class="mono">${name}</td>`,
      );
      expect(page, `${name} does not print its value`).toContain(
        `<td class="mono">${value}</td>`,
      );
    }
    // The pause is a word, not a rate: the paper publishes that decay is paused
    // and publishes no number, and a rate of zero would be a number nobody set.
    expect(page).toContain(`<td class="mono">STANDING_DECAY_PAUSED</td>`);
    expect(page).toContain(
      `<td class="mono">${POLICY.STANDING_DECAY_PAUSED ? "paused" : "active"}</td>`,
    );
    expect(page).toContain("there is no decay term at all");
  });

  it("groups the dispute and report numbers, and reads each from POLICY", () => {
    expect(page).toContain("Disputes and reports");
    for (const [name, value] of [
      ["FAILURE_REPORT_THRESHOLD", String(POLICY.FAILURE_REPORT_THRESHOLD)],
      ["DISPUTE_STAKE_STANDING", `${POLICY.DISPUTE_STAKE_STANDING} standing`],
      [
        "REVALIDATION_REQUEST_STAKE_STANDING",
        `${POLICY.REVALIDATION_REQUEST_STAKE_STANDING} standing`,
      ],
      [
        "REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW",
        String(POLICY.REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW),
      ],
    ] as const) {
      expect(page, `${name} has no row`).toContain(
        `<td class="mono">${name}</td>`,
      );
      expect(page, `${name} does not print its value`).toContain(
        `<td class="mono">${value}</td>`,
      );
    }
    // The stakes are placeholders in standing, and the page says so rather than
    // implying that a number nobody priced is a price. Nothing is staked in
    // money, because there is none (D-127).
    expect(page).toContain("Every stake above is standing");
    expect(page).toContain("there is no money here to stake");
    expect(page).not.toContain("DISPUTE_FILING_FEE_CENTS");
  });

  it("groups the attestation numbers, and reads all four from POLICY", () => {
    // M22's four, in their own group after the disputes. A literal here would
    // be a second place a published number lives, which is the one thing this
    // page exists to prevent.
    expect(page).toContain("Attestation");
    for (const [name, value] of [
      ["PROBE_SET_SIZE", `${POLICY.PROBE_SET_SIZE} probes`],
      ["PROBE_SET_MIN_CANDIDATES", String(POLICY.PROBE_SET_MIN_CANDIDATES)],
      ["ATTESTATION_SCORERS", String(POLICY.ATTESTATION_SCORERS)],
      ["ATTESTATION_WINDOW_HOURS", `${POLICY.ATTESTATION_WINDOW_HOURS} hours`],
    ] as const) {
      expect(page, `${name} has no row`).toContain(
        `<td class="mono">${name}</td>`,
      );
      expect(page, `${name} does not print its value`).toContain(
        `<td class="mono">${value}</td>`,
      );
    }
    // What each one fixes, in one line: the draw nobody controls, the thin
    // genesis tier, the scorers outside the model's operator, the deadline.
    expect(page).toContain("neither the model&#39;s operator nor the maintainer");
    expect(page).toContain("thin at genesis");
    expect(page).toContain("None of them may be under the model&#39;s own operator");
  });

  it("points at the JSON the kernel serves from the same module", () => {
    expect(page).toContain(`href="/policy"`);
    expect(page).toContain("Accept: application/json");
  });

  it("publishes the mirror as a group, read from the object it was handed", () => {
    // Section 11: the daily CC0 export. Every value is POLICY's own — the page
    // is handed a policy whose MIRROR is nothing like the real one, and it has
    // to print that one, because a page holding its own repository name could
    // point a fork somewhere the code never pushes.
    const other = renderPolicy(ctx, {
      ...POLICY,
      MIRROR: {
        repository: "test-owner/test-log",
        branch: "trunk",
        api: "https://api.test.invalid",
        web: "https://web.test.invalid",
        raw: "https://raw.test.invalid",
        license: "TEST-1.0",
      },
    } as unknown as typeof POLICY);
    for (const key of ["repository", "branch", "api", "web", "raw", "license"]) {
      expect(other, `MIRROR.${key} has no row`).toContain(`MIRROR.${key}`);
    }
    expect(other).toContain("test-owner/test-log");
    expect(other).toContain("trunk");
    expect(other).toContain("TEST-1.0");
    expect(other).toContain("https://raw.test.invalid");
    expect(other).not.toContain("nomankind-ai/log");
  });

  it("carries no script and no inline style", () => {
    expect(page).not.toContain("<script");
    expect(page).not.toContain(' style="');
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
      "/standing",
      "/operators/{id}/standing",
      "/operators/{id}/ledger",
      "/ledger",
      "/status",
      "/independence",
      "/mirror/latest",
      "/how-it-works",
    ];
    for (const path of paths) {
      expect(page, `${path} is not documented`).toContain(path);
    }
  });

  /**
   * The three answers a validator can give (D-121), on the row of the door that
   * takes them and in the words the code actually enforces: a rejection needs a
   * reason and may carry a measurement, an approval of an observed entry must,
   * and the extra standing is paid for measuring rather than for a direction.
   */
  it("names the three answers on the validate row, as the door takes them", () => {
    const opens = page.indexOf("/entries/{id}/validate");
    expect(opens).toBeGreaterThan(-1);
    const row = page.slice(opens, page.indexOf("/entries/{id}/reconfirm", opens));
    const words = row.replace(/\s+/g, " ");
    expect(words).toContain("There are three answers a validator can give");
    expect(words).toContain("approve:");
    expect(words).toContain("reject:");
    expect(words).toContain("test_accepted false:");
    // The door requires a reason on a rejection and a measurement only on an
    // approval, so the page may not promise the measurement either way.
    expect(words).toContain("may carry the measurement it found");
    expect(words).toContain("but is not required to");
    expect(words).toContain(
      "A negative result is a first-class answer and earns what a positive one earns",
    );
    expect(words).toContain(
      "STANDING_VALIDATION_REPRODUCED is paid beside it for a record carrying a passing measurement",
    );
    expect(words).not.toContain("the same standing whichever way");
  });

  it("says the entries listing is a page and names the JSON reads (D-124e, D-124f)", () => {
    const words = page.replace(/\s+/g, " ");
    // What is actually true of the route: /entries is not in NEGOTIATED_PATHS,
    // so it answers HTML whatever Accept says, and `limit` is not one of its
    // parameters, so it is refused as unknown_parameter with the Bad query page.
    // D-138 item 9 gave the listing a JSON twin: the same rows under the same
    // filters, for a program that would otherwise scrape the page.
    expect(words).toContain(
      "A page for a reader and a listing for a program: with Accept:" +
        " application/json it answers { entries, next, as_of }",
    );
    expect(words).toContain(
      "limit is refused as unknown_parameter, answered as the Bad query page" +
        " with 400",
    );
    // And where a program goes instead.
    const opens = page.indexOf("Reading entries as JSON");
    expect(opens).toBeGreaterThan(-1);
    const panel = page.slice(opens, page.indexOf("</section>", opens)).replace(/\s+/g, " ");
    expect(panel).toContain("GET /entries/{id}</dt>");
    expect(panel).toContain("without <span class=\"mono\">Accept: text/html</span>");
    expect(panel).toContain("GET /entries/{id}/events</dt>");
    expect(panel).toContain("GET /events</dt>");
    expect(panel).toContain("npm run export</dt>");
  });

  it("names the stop reasons and the validate door's errors array (D-124f)", () => {
    const opens = page.indexOf("What a validator's command stops on");
    expect(opens, "the panel is not on the page").toBeGreaterThan(-1);
    const panel = page.slice(opens, page.indexOf("</section>", opens)).replace(/\s+/g, " ");
    expect(panel).toContain("carries an <span class=\"mono\">errors</span> array");
    for (const reason of [
      "unregistered_operator",
      "legacy_entry",
      "schema_invalid",
      "entry_malformed",
    ]) {
      expect(panel, `${reason} is not explained`).toContain(
        `<dt class="mono">${reason}</dt>`,
      );
    }
    expect(panel).not.toContain("entry_withheld");
    // The validate row itself says the 422 carries the array, beside the word.
    const row = page.slice(
      page.indexOf("/entries/{id}/validate"),
      page.indexOf("/entries/{id}/reconfirm"),
    );
    const words = row.replace(/\s+/g, " ");
    expect(words).toContain(
      "schema_invalid — whose 422 carries an errors array naming each field that failed",
    );
    // legacy_entry is checked after the signature and the status and before the
    // schema, so it is named in that order and not appended to the end.
    expect(words.indexOf("legacy_entry")).toBeGreaterThan(
      words.indexOf("missing_observation"),
    );
    expect(words.indexOf("legacy_entry")).toBeLessThan(
      words.indexOf("schema_invalid"),
    );
    // And the panel keeps schema_invalid true of the other three doors.
    expect(panel).toContain(
      "on <span class=\"mono\">reconfirm</span>, <span class=\"mono\">dispute</span>" +
        " and <span class=\"mono\">revalidate</span> an entry sealed before schema" +
        " v0.7 still answers <span class=\"mono\">schema_invalid</span>",
    );
  });

  it("documents binding a second agent under an operator, and its refusals in order", () => {
    // M12's gap: an operator with one key had no way to add a second. The door
    // and the command are the record of how, so the page has to name both — and
    // the refusals in the order the kernel checks them, because a caller told
    // only that it was refused cannot tell which rule refused it.
    const opens = page.indexOf("/operators/{id}/agents");
    expect(opens, "the door is not documented").toBeGreaterThan(-1);
    // That row alone: the same words appear on the registration and the join
    // rows, so an order checked over the whole page would check nothing.
    const row = page.slice(opens, page.indexOf("/agents/{agent_id}", opens));

    let at = 0;
    for (const refusal of [
      "unregistered_operator",
      "not_operator_agent",
      "agent_bound",
      "bad_agent",
      "missing_attestation",
      "bad_attestation",
      "attestation_domain_mismatch",
    ]) {
      const found = row.indexOf(refusal, at);
      expect(
        found,
        `${refusal} is not named after the one before it`,
      ).toBeGreaterThan(-1);
      at = found + refusal.length;
    }
    // The three codes that are not 422, which a caller has to be able to tell
    // apart: an operator nobody registered, somebody else's agent, and an agent
    // that is already bound.
    expect(row).toContain("404 unregistered_operator");
    expect(row).toContain("403 not_operator_agent");
    expect(row).toContain("409 agent_bound");
    // The body it takes, and the record it answers with.
    expect(row).toContain("agent, attestation");
    expect(row).toContain("201 with the operator record");
    expect(page).toContain(
      `npm run register -- &lt;existing-key.json&gt; ${ctx.origin} &lt;operator-domain&gt; --bind &lt;new-key.json&gt;`,
    );
  });

  it("names every role the two capture routes serve", () => {
    // Section 4 and decision D-059 put a provider statement's page in the
    // archive beside the transcript, under the role `statement`. A caller
    // reading this page has to be told the archive answers for it, or the
    // third role looks like an address that is not served.
    const roles = "snapshot, receipt, statement, or report:&lt;seq&gt;";
    expect(page).toContain(roles);
    expect(page).toContain(
      "snapshot, receipt, statement, report:&lt;seq&gt;",
    );
    // The bytes route still says what it serves and how it serves them.
    expect(page).toContain("x-nomankind-archive-hash");
    expect(page).toContain(
      "final_url, status, headers, fetched_at, fetcher",
    );
  });

  it("documents the status endpoint's shape, and that it refuses nothing", () => {
    // A stage that is failing is an answer and not a refusal, which is the one
    // thing about this endpoint a caller has to be told: the only 503 is storage
    // being unreachable, and nothing else on it can turn into an error.
    expect(page).toContain("STATUS_ATTENTION_AFTER_INTERVALS");
    expect(page).toContain("STATUS_FAILING_AFTER_MINUTES");
    expect(page).toContain("ok, attention, failing, idle");
    expect(page).toContain(
      "a stage that is failing is an answer and not a refusal",
    );
    expect(page).toContain("503 storage_unreachable");
  });

  it("documents the standing and ledger routes with their shapes and refusals", () => {
    // Standing is served from what the sweep folded, at the position it folded
    // to, and the recompute is a command. The page has to say both: that is the
    // whole difference between a number a reader can check and a score
    // nomankind hands out.
    expect(page).toContain("as the sweep last folded it");
    expect(page).toContain("the recompute is the command");
    expect(page).toContain("formula");
    expect(page).toContain("stored");
    // The ledger doors carry no money any more (D-127): a row's unit is
    // standing, and the reconciliations are the published counts against the
    // rows written for them.
    expect(page).toContain("Nothing here is money and nothing is owed");
    expect(page).toContain("reconciliations");
    expect(page).toContain("no price and no share to reconcile against");
    for (const gone of [
      "READ_PRICE_MICROS_PER_READ",
      "PAYOUT_MINIMUM_MICROS",
      "PAYOUT_CYCLE",
      "HOLDBACK_DAYS",
    ]) {
      expect([gone, page.includes(gone)]).toEqual([gone, false]);
    }
    expect(page).toContain("404 not_found.");
  });

  it("gives standing a command beside the other offline checks", () => {
    expect(page).toContain(`npm run standing -- ${ctx.origin} &lt;operator&gt;`);
  });

  it("documents --sign on every command that reads the log", () => {
    // The flag no longer reaches content — the record is released at the seal
    // (D-127) — and it is still what names who is reading, so the commands
    // still carry it and the page still lists it.
    expect(page).toContain(
      `npm run standing -- ${ctx.origin} &lt;operator&gt; [--sign &lt;key.json&gt;]`,
    );
    expect(page).toContain(
      `npm run attest -- request &lt;model-key.json&gt; ${ctx.origin} [--sign &lt;key.json&gt;]`,
    );
    expect(page).toContain("&lt;attestation-id&gt; [--sign &lt;key.json&gt;]");
    expect(page).toContain("npm run checkpoint -- [--wait-seal]");
    // And what the flag actually buys, said where the flag is.
    expect(page.replace(/\s+/g, " ")).toContain(
      "the flag buys the run its operator's own daily cap rather than the",
    );
    expect(page).not.toContain("withheld inside the release window");
  });

  it("documents free access: the tiers table, the header, and every key door", () => {
    expect(page).toContain(">Free access: caps and keys</h2>");

    // Every registered tier, by its slug, with the cap and whether it takes a
    // key: a table that showed two of three would be documenting a ladder
    // nobody could see the top of.
    for (const [slug, tier] of Object.entries(POLICY.RATE_TIERS)) {
      expect(page, `${slug} is not in the tiers table`).toContain(
        `<td class="mono">${slug}</td>`,
      );
      expect(page).toContain(`<td class="mono">${tier.reads_per_day}</td>`);
    }

    expect(page).toContain("Authorization: Bearer nmk_");
    for (const header of [
      "x-nomankind-tier",
      "x-nomankind-limit",
      "x-nomankind-remaining",
    ]) {
      expect(page, `${header} is not documented`).toContain(header);
    }

    // The free door, and the four the paid loop left behind, each named with
    // the 410 it answers rather than deleted from the page (D-127).
    for (const door of [
      "/keys/tiers",
      "/keys/free",
      "/keys/me",
      "/keys/me/usage",
      "/keys/me/receipts",
    ]) {
      expect(page, `${door} is not documented`).toContain(door);
    }
    // The four doors of the paid loop are gone, addresses and all (D-127 item
    // 2): a removed route answers 404 like any unknown path, so the page names
    // none of them.
    for (const gone of [
      "POST /keys/checkout",
      "GET /keys/claim",
      "POST /keys/me/portal",
      "POST /stripe/webhook",
      "410 retired",
    ]) {
      expect([gone, page.includes(gone)]).toEqual([gone, false]);
    }

    // Every word the gate and the doors refuse in.
    for (const refusal of [
      "missing_key",
      "bad_key",
      "unknown_key",
      "rate_limited",
      "key_today",
      "no_keyed_tier",
      "bad_body",
    ]) {
      expect(page, `${refusal} is not named`).toContain(refusal);
    }
    // And the two that are not refusals any more (D-127 item 2): the page names
    // them once, to say they are gone, and nowhere as a thing a door answers.
    expect(page).toContain("went with the bill they were");
    expect(page).not.toContain("402");
    // And nothing about buying one.
    for (const gone of [
      "free_tier_needs_no_key",
      "unknown_session",
      "not_paid",
      "already_claimed",
      "payments_unavailable",
    ]) {
      expect([gone, page.includes(gone)]).toEqual([gone, false]);
    }

    // The 429 body, whole, because a caller that cannot see resets_at has to
    // guess when to come back. The cap in it is the standard tier's own number
    // read from policy, so a decision that moves the cap moves the example with
    // it and the docs cannot drift into documenting a cap nobody is held to.
    const cap = POLICY.RATE_TIERS["standard"]!.reads_per_day;
    expect(page).toContain(
      `{ "error": "rate_limited", "tier": "standard", "limit": ${cap},`,
    );
    expect(page).toContain(`"used": ${cap}, "resets_at":`);
    expect(page).toContain("retry-after");

    // The key is shown once, at the free door, and nowhere else ever again.
    expect(page).toContain("The secret is shown exactly once");
  });

  it("documents what a keyed read's receipt carries, and how it reconciles", () => {
    expect(page).toContain(">Receipts and the key's own counter</h2>");
    expect(page).toContain("key_counter");
    expect(page).toContain("read_count");
    // The day's counts are evidence of use and never a bill (D-127).
    expect(page).toContain("evidence that the record is used");
    expect(page).not.toContain("paid.keys");
    // A receipt issued before the two fields existed still verifies: the page
    // has to say so, or every M17 receipt looks broken.
    expect(page).toContain("carries neither property at all");
  });

  it("documents the webhooks, their kinds, and the exact signature recipe", () => {
    expect(page).toContain(">Webhooks and change alerts</h2>");

    for (const door of [
      "/keys/me/webhooks",
      "/keys/me/webhooks/{id}",
      "/keys/me/webhooks/{id}/deliveries",
    ]) {
      expect(page, `${door} is not documented`).toContain(door);
    }
    for (const refusal of ["bad_url", "unknown_kind", "unknown_domain", "endpoint_limit"]) {
      expect(page, `${refusal} is not named`).toContain(refusal);
    }

    // Every kind, from POLICY.
    expect(page).toContain(POLICY.ALERT_KINDS.join(", "));

    // And the seventh, which is the one a subscriber cannot work out from the
    // log: no event carries it, so the page has to say where its position, its
    // seal and its `at` come from instead.
    expect(POLICY.ALERT_KINDS).toContain("stale");
    const flat = page.replace(/\s+/g, " ");
    expect(flat).toContain("the only one no event carries");
    expect(flat).toContain("the entry's own submission");
    expect(flat).toContain("the day the window ran out");

    // The four headers a delivery carries.
    for (const header of [
      "x-nomankind-alert",
      "x-nomankind-kind",
      "x-nomankind-signature",
      "content-type: application/json",
    ]) {
      expect(page, `${header} is not documented`).toContain(header);
    }

    // The recipe, exactly: the bytes, the algorithm, and the bytes to verify
    // against. A subscriber cannot check a signature from a description of one.
    expect(page).toContain(HASH_TAG_ALERT);
    expect(page).toContain("HMAC-SHA256");
    expect(page).toContain("Verify against the bytes that arrived");

    // The retry ladder and the timeout, both from POLICY.
    expect(page).toContain(POLICY.ALERT_RETRY_MINUTES.join(", "));
    expect(page).toContain(`${POLICY.ALERT_TIMEOUT_MS} ms`);
    expect(page).toContain(String(POLICY.ALERT_ENDPOINTS_PER_KEY));
  });

  it("names the one unit there is, and says there is no other", () => {
    expect(page).toContain(">Units</h2>");
    expect(page).toContain("One unit appears on the ledger");
    expect(page).toContain("Standing units, which are not money");
    expect(page).toContain("There is no micro-USD");
    expect(page).not.toContain("a millionth of a dollar: 1,000,000 to the dollar");
    expect(page).not.toContain("cents");
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
    // keygen takes a name and writes outside the clone (D-016). The page said
    // `-- <path>`, which is the one thing the command refuses.
    expect(page).toContain(
      "npm run keygen -- [&lt;name&gt; | --out &lt;path&gt;]",
    );
    expect(page).toContain("~/.nomankind/keys/&lt;name&gt;.json");
    expect(page).not.toContain("npm run keygen -- &lt;path&gt;");
  });

  it("spells the example commands against this origin", () => {
    expect(page).toContain(ctx.origin);
  });

  it("names what is not built yet with its milestone", () => {
    expect(page).toContain("M25");
    // M24 built the keys, the paid tiers, the webhooks and the rate limits, so
    // the row is gone: a path that exists listed as unbuilt is the same lie as
    // a documented path that answers 404.
    expect(page).not.toContain("API keys, paid tiers, webhooks, rate limits");
    expect(page).not.toContain(`<td class="mono">M24</td>`);
    // M23 built the mirror, so the row is gone: a path that exists listed as
    // unbuilt is the same lie as a documented path that answers 404.
    expect(page).not.toContain("The log mirror");
    expect(page).not.toContain(`<td class="mono">M23</td>`);
    // M21 built standing and the ledger, so the row is gone: a path that exists
    // listed as unbuilt is the same lie as a documented path that answers 404.
    expect(page).not.toContain("Standing and the ledger endpoints");
    expect(page).not.toContain(`<td class="mono">M21</td>`);
    // M22 built the attestation doors and the confidence inputs, so the row is
    // gone: a path that exists listed as unbuilt is the same lie as a
    // documented path that answers 404.
    expect(page).not.toContain("Drift attestation and confidence inputs");
    expect(page).not.toContain(`<td class="mono">M22</td>`);
  });

  it("documents all seven attestation and confidence routes, in order", () => {
    const paths = [
      "POST",
      "/attestations",
      "/attestations/{id}/answers",
      "/attestations/{id}/score",
      "/attestations/{id}",
      "/operators/{id}/attestations",
      "/entries/{id}/confidence-inputs",
    ];
    for (const path of paths) {
      expect(page, `${path} is not documented`).toContain(path);
    }
    // The three writes come before the reads that serve what they produced: an
    // attestation is one sequence, and the score route read on its own is the
    // end of a story.
    let at = page.indexOf(">Attestation and confidence</h2>");
    expect(at).toBeGreaterThan(-1);
    for (const path of [
      "/attestations/{id}/answers",
      "/attestations/{id}/score",
      "/operators/{id}/attestations",
      "/entries/{id}/confidence-inputs",
    ]) {
      const next = page.indexOf(path, at);
      expect(next, `${path} is out of order`).toBeGreaterThan(at);
      at = next;
    }
  });

  it("documents the duplicate claim at all three doors it shows up in", () => {
    // Decision D-085. The mechanical duplicate is refused at submit, the
    // judgment is a validator's rejection in a published form, and both reach
    // the confidence inputs. A caller reading this page has to be told all
    // three, or the 422 looks like a refusal with no way to answer it.
    const submit = page.indexOf("/entries<");
    const refusals = page.indexOf("duplicate_claim (", submit);
    expect(refusals).toBeGreaterThan(-1);
    expect(page).toContain("the answer carries duplicate_of");
    // Refused where the kernel refuses it: after the supersession refusals and
    // before anything is fetched.
    expect(refusals).toBeGreaterThan(page.indexOf("category_mismatch", submit));
    expect(refusals).toBeLessThan(page.indexOf("snapshot_mismatch", submit));

    // The published form, verbatim, on the validate row.
    expect(page).toContain("duplicate_claim:&lt;entry id&gt;");
    expect(page).toContain("nothing new is signed");

    // And the two fields the confidence inputs publish for it.
    expect(page).toContain("duplicate_of and duplicate_rejections");
  });

  it("lists the answer and score refusals in the kernel's own order", () => {
    let at = page.indexOf("/attestations/{id}/answers");
    for (const reason of ANSWER_REFUSALS) {
      const next = page.indexOf(reason, at);
      expect(next, `${reason} is out of order`).toBeGreaterThan(at);
      at = next;
    }
    at = page.indexOf("/attestations/{id}/score");
    for (const reason of SCORE_REFUSALS) {
      const next = page.indexOf(reason, at);
      expect(next, `${reason} is out of order`).toBeGreaterThan(at);
      at = next;
    }
    // The request door's own refusals, in the order it checks them.
    at = page.indexOf(">Attestation and confidence</h2>");
    for (const reason of [
      "bad_body",
      "attestation_open",
      "beacon_unavailable",
      "no_pool_snapshot",
      "snapshot_after_beacon",
      "insufficient_candidates",
      "empty_pool",
      "insufficient_scorers",
      // The draw names operators; the scorer beside each one is the first agent
      // bound under it, and an operator with none is refused rather than
      // published as a scorer nobody can answer for.
      "no_agent_for_operator",
    ]) {
      const next = page.indexOf(reason, at);
      expect(next, `${reason} is out of order`).toBeGreaterThan(at);
      at = next;
    }
  });

  it("says what the attestation reads do, rather than a refusal they cannot make", () => {
    // A documented refusal a route never makes is the same lie as a documented
    // path that answers 404. The listing narrows a bad query instead of
    // refusing it, and the operator read answers two empty lists for an
    // operator it has never heard of, so neither row may claim one.
    const from = page.indexOf(">Attestation and confidence</h2>");
    expect(from).toBeGreaterThan(-1);
    const to = page.indexOf('<h2 class="panel-title">', from + 1);
    expect(to).toBeGreaterThan(from);
    const section = page.slice(from, to);
    expect(section).not.toContain("bad_query");
    // The single read parses the id before it looks for the row, so it has a
    // refusal of its own and the page says both.
    expect(section).toContain("400 bad_id; 404 not_found.");
    expect(section).toContain("both lists empty");
  });

  it("gives the attestation writes their commands, and submit its receipt", () => {
    expect(page).toContain(
      `npm run attest -- request &lt;model-key.json&gt; ${ctx.origin}`,
    );
    expect(page).toContain("npm run attest -- answer");
    expect(page).toContain("npm run attest -- score");
    expect(page).toContain("--drift");
    expect(page).toContain("--receipt &lt;receipt.json&gt;");
  });

  it("lists POST validate's refusals in VALIDATION_REFUSALS order", () => {
    // The validation door applies src/validate.ts's list in its own order, and
    // M20 put `original_signer` into it between submitter_operator and
    // maintainer_operator: no operator that signed the original may judge the
    // correction filed against it. The page has to say so where a caller meets
    // it, not at the end of the row.
    let at = page.indexOf("/entries/{id}/validate");
    expect(at).toBeGreaterThan(-1);
    for (const reason of VALIDATION_REFUSALS) {
      const next = page.indexOf(reason, at);
      expect(next, `${reason} is out of order`).toBeGreaterThan(at);
      at = next;
    }
  });

  it("documents the dispute, revalidation and failure-report doors", () => {
    for (const path of [
      "/entries/{id}/dispute",
      "/entries/{id}/revalidate",
      "/entries/{id}/revalidate/resolve",
      "/entries/{id}/failure-reports",
    ]) {
      expect(page, `${path} is not documented`).toContain(path);
    }
    // They exist now, so they are gone from the list of what does not.
    expect(page).not.toContain(
      "Disputes, revalidation requests, failure reports",
    );
  });

  it("lists each new route's refusals in the order the route checks them", () => {
    const inOrder = (label: string, reasons: readonly string[]): void => {
      let at = page.indexOf(label);
      expect(at, `${label} is not on the page`).toBeGreaterThan(-1);
      for (const reason of reasons) {
        const next = page.indexOf(reason, at);
        expect(next, `${label}: ${reason} is out of order`).toBeGreaterThan(at);
        at = next;
      }
    };

    inOrder("/entries/{id}/dispute", [
      "bad_id",
      "bad_body",
      "the request verdicts",
      "not_found",
      // The QA of 2026-09-12: an author does not challenge its own entry, and
      // the rule is asked before the door settles which key the filer is —
      // otherwise the envelope is a way around it — so the page says it there.
      "self_dispute",
      "author_mismatch",
      // Section 9: standing gates the stake, and the gate stands in front of
      // the submission pipeline because that pipeline fetches the cited page —
      // a filing that cannot cover its stake costs the log no fetch at all.
      "insufficient_standing",
      "POST /entries refusal",
      "entry_not_verified",
      "not_correction",
      "missing_citation",
      "subject_mismatch",
      "dispute_open",
      // Decision D-080: the source gate is asked a second time here, about the
      // entry being challenged, after the filing rules and before the links.
      "unknown_authority",
      "source_not_official",
      "bad_report_link",
      "bad_revalidation_link",
      // The target's rederivation is schema-checked last, after every filing
      // rule has passed, so schema_invalid closes the row.
      "schema_invalid",
    ]);

    inOrder("/entries/{id}/revalidate<", [
      "bad_id",
      "bad_body",
      "the request verdicts",
      "not_found",
      "entry_not_verified",
      "entry_stale",
      "bare_key",
      "cap_exceeded",
      "request_open",
      "insufficient_standing",
      "schema_invalid",
    ]);

    inOrder("/entries/{id}/revalidate/resolve", [
      "bad_id",
      "bad_body",
      "the request verdicts",
      "not_found",
      "no_open_request",
      "not_assigned",
      "agent_mismatch",
      "bad_signed_at",
      "bad_record_signature",
      "schema_invalid",
    ]);

    inOrder("/entries/{id}/failure-reports", [
      "bad_id",
      "bad_body",
      "the request verdicts",
      "not_found",
      // The door reads the artifact's kind off its key set before it can pick a
      // shape check at all, so unknown_artifact comes first and never last.
      "unknown_artifact",
      "transcript_shape",
      "receipt_shape",
      "unknown_method",
      "billing_shape",
      "redacted_load_bearing",
      "entry_not_verified",
      "empty_observed",
      "bad_artifact_hash",
      "duplicate_reporter",
      // The archive names the 1F916 identity that put the artifact there, so
      // this door needs the fetcher configured exactly as POST /entries does.
      "fetcher_not_configured",
      "schema_invalid",
    ]);
  });

  it("says in words what each mechanism is, and what a stake is put up in", () => {
    expect(page).toContain("A dispute is a challenge to a verified entry");
    expect(page).toContain("A revalidation request is an operator asking");
    expect(page).toContain("A failure report is a signed report");
    expect(page).toContain("distinct registered\n          operators");
    expect(page).toContain("drawn from the trusted pool by the public randomness");
    // Decision D-127: the stake is contribution and so is the reward. Nothing
    // is clawed back, because nothing was ever paid out.
    expect(page).toContain("Filing takes a stake, and the stake is contribution");
    expect(page).toContain(
      `${POLICY.DISPUTE_STAKE_STANDING} standing to file a dispute`,
    );
    expect(page).toContain("STANDING_DISPUTE_UPHELD");
    expect(page).toContain("STANDING_OVERTURNED_SIGNER");
    expect(page).toContain("Nothing is clawed back");
    expect(page).not.toContain("filing fee");
  });

  it("gives the three 409 conflicts and never a status of its own", () => {
    for (const conflict of [
      "409 duplicate_entry",
      "409 dispute_open",
      "409 request_open",
      "409 duplicate_reporter",
    ]) {
      expect(page, `${conflict} is not named`).toContain(conflict);
    }
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

  it("documents domain= on every door that takes it", () => {
    // Four doors take it: the two JSON readers and the two browsing pages.
    // A parameter a route accepts and the page does not name is a filter no
    // caller knows exists.
    for (const marker of [
      "subject=<s>, category=<c>, domain=<slug>",
      // D-138 put min_class between the source floor and the domain on /sync.
      "min_source=official|recognized, min_class=community|mixed|registered, domain=<slug>",
      "category=<c>, status=<s>, domain=<slug>",
    ]) {
      expect(page, `${marker} is not documented`).toContain(
        marker.replaceAll("<", "&lt;").replaceAll(">", "&gt;"),
      );
    }
    // Each names unknown_domain where its own parser raises it.
    const inOrder = (label: string, reasons: readonly string[]): void => {
      let at = page.indexOf(label);
      expect(at, `${label} is not on the page`).toBeGreaterThan(-1);
      for (const reason of reasons) {
        const next = page.indexOf(reason, at);
        expect(next, `${label}: ${reason} is out of order`).toBeGreaterThan(at);
        at = next;
      }
    };
    inOrder('<td class="mono">/read</td>', READ_QUERY_REFUSALS);
    inOrder('<td class="mono">/sync</td>', SYNC_QUERY_REFUSALS);
    // The listing's own refusals, in src/ui/query.ts's order.
    inOrder('<td class="mono">/entries</td>', [
      "unknown_parameter",
      "repeated_parameter",
      "bad_category",
      "bad_status",
      "unknown_domain",
      "bad_source",
      "bad_tier",
      "bad_min_class",
      "bad_fresh",
      "bad_before",
    ]);
    // The home page refuses a slug nobody registered rather than counting the
    // whole log under a name the reader mistyped.
    inOrder('<td class="mono">/</td>', ["domain=&lt;slug&gt;", "unknown_domain"]);
  });

  it("documents the join route with JOIN_REFUSALS in the kernel's order", () => {
    expect(page).toContain("/operators/{id}/domains");
    let at = page.indexOf("/operators/{id}/domains");
    for (const reason of [
      "bad_id",
      "bad_body",
      "the request verdicts",
      "not_found",
      "agent_mismatch",
      ...JOIN_REFUSALS,
    ]) {
      const next = page.indexOf(reason, at);
      expect(next, `${reason} is out of order`).toBeGreaterThan(at);
      at = next;
    }
    // The body it takes, and what registration itself now names.
    expect(page).toContain("attestation { version, domain, signed_at, signature }");
    expect(page).toContain("unregistered_domain");
    expect(page).toContain("attestation_domain_mismatch");
  });

  it("names the submission's domain and source refusals where the door checks them", () => {
    // src/submit.ts puts the domain three straight after bad_norm_version and
    // the source policy's two straight after them (decision D-080), so the page
    // does too: a caller told the first thing that was wrong can fix it.
    const run = SUBMISSION_REFUSALS.slice(
      SUBMISSION_REFUSALS.indexOf("bad_norm_version"),
      SUBMISSION_REFUSALS.indexOf("bad_submitted_at"),
    );
    expect([...run]).toEqual([
      "bad_norm_version",
      "missing_domain",
      "unregistered_domain",
      "category_not_in_domain",
      // D-096: a subject that must carry a version and does not is refused
      // where the category itself is, and before the source policy is asked.
      "bad_subject_version",
      "unknown_authority",
      "source_not_official",
    ]);
    let at = page.indexOf('<td class="mono">/entries</td>', page.indexOf("Write path"));
    expect(at).toBeGreaterThan(-1);
    for (const reason of run) {
      const next = page.indexOf(reason, at);
      expect(next, `${reason} is out of order`).toBeGreaterThan(at);
      at = next;
    }
  });

  it("documents the six refusals the new domains brought, on their own doors", () => {
    // Decision D-096. Each is named where the door that raises it is
    // documented, and never anywhere else: a caller reading the validate row
    // has to be told what a subject's own authority costs them, and a caller
    // reading the captures row has to be told why bytes that exist are a 403.
    // One table row is one door, so the needle has to be inside the row that
    // names the path and not merely somewhere on the page.
    const rows = page.split("<tr>");
    const rowFor = (method: string, path: string): string => {
      const found = rows.filter(
        (row) =>
          row.includes(`<td class="mono">${path}</td>`) &&
          row.includes(`>${method}</td>`),
      );
      expect(found, `${method} ${path} is not a row of its own`).toHaveLength(1);
      return found[0]!;
    };
    const documents = (
      method: string,
      path: string,
      needles: readonly string[],
    ): void => {
      const row = rowFor(method, path);
      for (const needle of needles) {
        expect(row, `${method} ${path}: ${needle} is not documented`).toContain(
          needle,
        );
      }
    };
    documents("GET", "/captures/{hash}", ["undisclosed", "disclose_after"]);
    documents("POST", "/entries/{id}/validate", ["subject_authority"]);
    documents("POST", "/entries/{id}/reconfirm", [
      "version_stale",
      "subject_authority",
    ]);
    documents("POST", "/entries", [
      "bad_subject_version",
      "disclosure_missing",
      "disclosure_mismatch",
    ]);
    // And the body field the disclosure refusals are about.
    expect(page).toContain("disclosure only when the transcript carries a");
  });

  it("documents the source policy: the classes, the gate and the host rule", () => {
    // Decision D-080. The API page is where a caller learns why a citation that
    // hashes correctly can still be refused, so it has to carry the three
    // classes, the two refusals, the reader's own demand, and the sentence that
    // the class is not the judgment.
    expect(page).toContain("Which sources may be cited for what");
    for (const word of [
      "official",
      "recognized",
      "other",
      "source_not_official",
      "unknown_authority",
      "min_source",
    ]) {
      expect(page, `${word} is not documented`).toContain(word);
    }
    // The correction goes through the same pipeline, so it obeys the same rule.
    expect(page).toContain("a correction of a pricing claim must");
    // And the judgment the policy does not automate.
    expect(page).toContain("a validator's approval asserts that the");
  });

  it("carries min_source on both reader doors and source on the listing", () => {
    const readRow = page.indexOf('<td class="mono">/read</td>');
    expect(page.indexOf("min_source=official|recognized", readRow)).toBeGreaterThan(
      readRow,
    );
    const syncRow = page.indexOf('<td class="mono">/sync</td>');
    expect(page.indexOf("min_source=official|recognized", syncRow)).toBeGreaterThan(
      syncRow,
    );
    expect(page).toContain("source=official|recognized|other");
  });

  it("counts the signed core keys rather than spelling the number out", () => {
    expect(page).toContain(`the ${CORE_KEYS.length} signed core keys`);
    expect(page).toContain(`${CORE_KEYS.length}-key core`);
  });

  it("names the verifier's schema refusal and the version it checks against", () => {
    expect(page).toContain("unsupported_schema_version");
    expect(page).toContain(POLICY.SCHEMA_VERSION);
  });

  it("gives register its domain and join switches, and submit its domain field", () => {
    expect(page).toContain("--domain &lt;slug&gt;");
    expect(page).toContain("--join &lt;slug&gt;");
    expect(page).toContain("npm run register --");
    // The fields file names the domain the author signs; a missing one is
    // bad_fields before any I/O rather than a default nobody chose.
    expect(page).toContain("bad_fields");
  });

  it("documents the mirror endpoint in both of its shapes", () => {
    // Section 11: the daily CC0 export, and the two 404 reasons a caller has to
    // be able to tell apart — an environment that pushes nothing, and one whose
    // first export is still owed.
    expect(page).toContain("The mirror and the fork kit");
    expect(page).toContain('"error": "no_export"');
    expect(page).toContain("mirror_not_configured");
    expect(page).toContain("no_export_yet");
    for (const field of [
      "exported_at",
      "commit",
      "tree",
      "head",
      "seal_seq",
      "files_changed",
      "raw_url",
    ]) {
      expect(page, `${field} is not in the mirror shape`).toContain(field);
    }
  });

  it("gives the mirror and verify-mirror commands their whole signatures", () => {
    expect(page).toContain(`npm run mirror -- ${ctx.origin} ./mirror`);
    expect(page).toContain(
      "npm run verify-mirror -- ./mirror/&lt;env&gt; [--captures &lt;url-or-dir&gt;] [--entry &lt;id&gt;]",
    );
  });

  it("publishes no split, no price and no share at all (D-127)", () => {
    // Section 9's old promise was about money; the record is free, so what the
    // page says now is what a contributor earns instead — standing, named on
    // the policy page — and every word of the split is gone.
    expect(page).toContain("What a contributor earns is standing and nothing else");
    // The one place micro-USD is still named is the Units panel, saying there
    // is no amount in one anywhere.
    expect(page).toContain("There is no micro-USD");
    for (const gone of [
      "What the ledger pays, per evidence tier",
      "READ_SHARE_SPLIT",
      "read_share",
      "contributor pool",
    ]) {
      expect([gone, page.includes(gone)]).toEqual([gone, false]);
    }
  });

  it("counts the status stages as the status rules count them", () => {
    // The count is read from the status rules themselves rather than spelled
    // here, so a stage added to the pipeline cannot leave the endpoint's own
    // description documenting a shape the route no longer answers.
    expect(page).toContain(`${STAGE_COUNT} of them`);
    expect(page).not.toContain("thirteen of them");
  });

  it("carries no script and no inline style", () => {
    expect(page).not.toContain("<script");
    expect(page).not.toContain(' style="');
  });
});

// ---------------------------------------------------------------------------
// How it works: the tenth stage
// ---------------------------------------------------------------------------

/**
 * A log holding nothing at all, which is what production is the day it opens.
 *
 * The tenth stage is the one panel that reads no live value — what is on sale
 * and what an alert can be about are policy rather than a record — so an empty
 * log is the honest fixture for it: everything the test pins below has to be
 * there before the first entry is.
 */
const EMPTY_PIPELINE: HowItWorksData = {
  entry: null,
  capture: null,
  pool: { names: [], trusted: 0, registered: 0 },
  validation: null,
  seal: null,
  anchor: null,
  readCount: null,
  overturned: null,
  stale: 0,
  nextWindowEnds: null,
  standing: { position: null, rows: [] },
  reconciliation: null,
  attestation: null,
  syncFrom: 0,
  mirror: null,
};

describe("renderHowItWorks: free access, caps, and alerts", () => {
  const page = renderHowItWorks(
    { ...ctx, path: "/how-it-works" },
    EMPTY_PIPELINE,
  );
  const STAGE = "Free access, caps, and alerts";

  it("puts the stage in the stack and in the strip, tenth and after the mirror", () => {
    expect(page).toContain('class="panel" id="s10"');
    expect(page).toContain('<span class="stage-num">10</span>');
    expect(page).toContain(STAGE);
    expect(page).toContain("SECTION 9 · THE RECORD IS FREE");
    // The strip is the page's own table of contents: a stage in the stack and
    // not in it is a stage a reader never learns is there.
    expect(page).toContain('class="step" href="#s10"');
    expect(page.indexOf("Mirror and fork")).toBeLessThan(page.indexOf(STAGE));
  });

  it("names the policy numbers it runs under, through the link to /policy", () => {
    const tiers = Object.keys(POLICY.RATE_TIERS).join("/");
    expect(page).toContain(
      `<a href="/policy">RATE_TIERS ${tiers} · ALERT_KINDS ${POLICY.ALERT_KINDS.length}</a>`,
    );
  });

  it("links into the live record rather than describing it", () => {
    expect(page).toContain('<a href="/keys/tiers">GET /keys/tiers</a>');
    expect(page).toContain('<a href="/status">GET /status</a>');
    // Every tier there is, with its own cap: a ladder shown two rungs of is a
    // ladder nobody can see the top of.
    for (const [slug, tier] of Object.entries(POLICY.RATE_TIERS)) {
      expect(page, `${slug} is not named`).toContain(
        `${slug} ${tier.reads_per_day} a day`,
      );
    }
  });

  it("says what D-127 says: the record is free and a key is an identity", () => {
    // The prose wraps, so the whitespace is collapsed before a sentence of it
    // is looked for.
    const prose = page.replace(/\s+/g, " ");
    expect(prose).toContain("The record is free, from the seal (decision D-127)");
    expect(prose).toContain("no paid tier, no key to buy and no read share");
    expect(prose).toContain("POST /keys/free");
    expect(prose).toContain("A tier is that daily cap and nothing else");
    expect(prose).toContain(
      "as evidence the record is used rather than as a bill",
    );
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

  it("names both joining steps, and no money one (D-127)", () => {
    expect(page).toContain("Prove a domain");
    expect(page).toContain("Name a domain and sign its independence attestation");
    expect(page).toContain("Joining takes two steps");
    expect(page).not.toContain("payout");
  });

  it("shows every registered domain's attestation sentence and version", () => {
    // The attestation is per domain (decision D-071): a page showing one
    // sentence for a log that holds two domains would be showing an operator
    // the wrong string to sign.
    for (const [slug, domain] of Object.entries(DOMAINS)) {
      expect(page, `${slug} has no attestation block`).toContain(slug);
      expect(page, `${slug}'s sentence is not verbatim`).toContain(
        domain.attestation.text,
      );
      expect(page, `${slug}'s version is missing`).toContain(
        domain.attestation.version,
      );
      expect(page, `${slug}'s name is missing`).toContain(domain.name);
      expect(page, `${slug}'s exclusion rule is missing`).toContain(
        domain.excluded_parties.rule,
      );
    }
  });

  it("names the domain in the joining steps and in the register body", () => {
    expect(page).toContain("Name a domain and sign its independence attestation");
    expect(page).toContain(`"domain": "${DEFAULT_DOMAIN}"`);
    expect(page).toContain("POST /operators/{id}/domains");
    // The signed object gained the key, and a pre-v0.7 attestation did not.
    expect(page).toContain("agent, domain, operator, signed_at, text");
  });

  it("shows the register body and points at the API page", () => {
    expect(page).toContain("POST /operators");
    expect(page).toContain(`href="/api"`);
  });

  it("points a candidate at the demo dry run before the one that counts", () => {
    expect(page).toContain("Practice on demo first");
    expect(page).toContain(`href="/dry-run"`);
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

/**
 * The dry-run page (Section 11: "each candidate validates one seeded entry in a
 * public dry run before being named").
 *
 * The page is a set of commands, so the tests hold it to the two things a set of
 * commands can be wrong about: which log they point at, and whether a number in
 * them is the policy module's or the page's own. The dry run is practiced on
 * demo from every environment, so a production reader has to be handed demo's
 * host and told why — a page that pointed its commands at the host it happened
 * to be fetched from would be two different rehearsals.
 */
describe("renderDryRun", () => {
  const DEMO_ORIGIN = "https://demo.nomankind.ai";
  const PRODUCTION_ORIGIN = "https://app.nomankind.ai";
  // A demo context whose origin is not the constant, because a demo run served
  // from the local host has to be handed its own host and not the page's
  // built-in one: with the two equal, the demo branch could ignore ctx.origin
  // and every assertion here would still pass.
  const LOCAL_DEMO_ORIGIN = "http://127.0.0.1:8787";

  const demoCtx: PageContext = {
    environment: "demo",
    path: "/dry-run",
    origin: LOCAL_DEMO_ORIGIN,
    canonical_origin: "https://demo.nomankind.ai",
  };
  const productionCtx: PageContext = {
    environment: "production",
    path: "/dry-run",
    origin: PRODUCTION_ORIGIN,
    canonical_origin: "https://app.nomankind.ai",
  };

  const page = renderDryRun(demoCtx);

  /** One line of prose, however the template wrapped it. */
  function squeeze(rendered: string): string {
    return rendered.replace(/\s+/g, " ");
  }

  /** Every command block that names a log at all, with its origin in it. */
  function commandsNamingALog(rendered: string): string[] {
    return [...rendered.matchAll(/<pre class="block mono">([\s\S]*?)<\/pre>/g)]
      .map((match) => match[1] ?? "")
      .filter((block) => block.includes("npm run") && block.includes("://"));
  }

  it("names the three answers a validator can give, in step 4", () => {
    const step = page.indexOf("Step 4. Judge one entry");
    expect(step).toBeGreaterThan(-1);
    const panel = squeeze(page.slice(step, page.indexOf("Step 5.", step)));
    expect(panel).toContain("There are three answers to give");
    expect(panel).toContain(">approve</span>");
    expect(panel).toContain(">reject</span>");
    expect(panel).toContain(">test_accepted</span> false");
    // What the door does: a reason always, a measurement on a rejection only if
    // the validator has one, and the judgment recorded either way.
    expect(panel).toContain("the reason is required and public");
    expect(panel).toContain("the door does not require one");
    expect(panel).toContain(
      "recorded on a rejection and an approval alike",
    );
    expect(panel).toContain(
      "A negative result is a first-class answer and earns what a positive one earns",
    );
    expect(panel).toContain(
      "the extra credit for measuring is earned for a passing measurement",
    );
  });

  it("walks the six steps in order", () => {
    const headings = [
      "What you need",
      "Step 1. Make a key",
      "Step 2. Publish the TXT record",
      "Step 3. Register",
      "Step 4. Judge one entry",
      "Step 5. See it in the log",
      "Step 6. Verify it yourself",
      "What demo does not do",
      "How it counts",
    ];
    let at = -1;
    for (const heading of headings) {
      const next = page.indexOf(`<h2 class="panel-title">${heading}</h2>`);
      expect(next, `${heading} is not a panel title`).toBeGreaterThan(at);
      at = next;
    }
  });

  it("gives each command its real argument form", () => {
    // keygen takes a name, and the key lands outside the clone (D-016): a guide
    // that taught `./demo-key.json` taught a path a `git add .` would commit.
    expect(page).toContain("npm run keygen -- demo");
    expect(page).not.toContain("npm run keygen -- ./");
    expect(page).toContain("~/.nomankind/keys/demo.json");
    expect(page).toContain(
      `npm run register -- ~/.nomankind/keys/demo.json ${LOCAL_DEMO_ORIGIN} &lt;your domain&gt;`,
    );
    expect(page).toContain(
      `npm run validate -- ~/.nomankind/keys/demo.json ${LOCAL_DEMO_ORIGIN} &lt;entry-id&gt;`,
    );
    expect(page).toContain("--duplicate-of &lt;entry-id&gt;");
    expect(page).toContain(
      `npm run export -- ${LOCAL_DEMO_ORIGIN} &lt;entry-id&gt; ./bundle`,
    );
    expect(page).toContain(
      "npm run verify -- ./bundle/entry.json ./bundle/log.json",
    );
    // The register command carries no --genesis: only the maintainer key names
    // anyone, which the page says in prose right under it.
    const register = commandsNamingALog(page).find((block) =>
      block.includes("npm run register"),
    );
    expect(register).toBeDefined();
    expect(register).not.toContain("--genesis");
    expect(squeeze(page)).toContain(
      `No <span class="mono">--genesis</span>. That flag posts the`,
    );
    expect(page).toContain("&lt;your domain&gt;");
    expect(page).toContain(`${TXT_RECORD_PREFIX}.&lt;your domain&gt;`);
    expect(page).toContain("status=draft");
  });

  it("points every command at this demo host, and says nothing about it, on demo", () => {
    const blocks = commandsNamingALog(page);
    expect(blocks.length).toBeGreaterThan(0);
    for (const block of blocks) {
      expect(block, `a command does not name ${LOCAL_DEMO_ORIGIN}`).toContain(
        LOCAL_DEMO_ORIGIN,
      );
      // The demo branch reads ctx.origin, so the built-in demo host is nowhere
      // in a command a demo reader is handed.
      expect(block, `a command names ${DEMO_ORIGIN}`).not.toContain(
        DEMO_ORIGIN,
      );
    }
    expect(squeeze(page)).not.toContain(
      "The dry run is practiced on demo, so the commands below point there.",
    );
  });

  it("points every command at demo from another environment, and says why", () => {
    const elsewhere = renderDryRun(productionCtx);
    const blocks = commandsNamingALog(elsewhere);
    expect(blocks.length).toBeGreaterThan(0);
    for (const block of blocks) {
      expect(block, `a command does not name ${DEMO_ORIGIN}`).toContain(
        DEMO_ORIGIN,
      );
    }
    // Below the head, and only below it. The production log is named nowhere a
    // reader could copy it from — not in a command, not in prose — but the head
    // of a page served from production is canonical at production (D-114), so
    // the one place its origin does appear is the tag that says which address
    // this page is. Both halves asserted, or the narrowing would hide a leak.
    const body = elsewhere.slice(elsewhere.indexOf("</head>"));
    expect(body).not.toContain(PRODUCTION_ORIGIN);
    expect(elsewhere).toContain(
      `<link rel="canonical" href="${PRODUCTION_ORIGIN}/dry-run" />`,
    );
    expect(squeeze(elsewhere)).toContain(
      "This is the production log. The dry run is practiced on demo, so the" +
        " commands below point there.",
    );
  });

  it("takes its numbers from the policy module", () => {
    expect(page).toContain(`${ASSIGNMENT_WINDOW_HOURS} hours to answer`);
    expect(page).toContain(`${SEAL_INTERVAL_MINUTES} minutes`);
  });

  it("credits --sign to the key registered in step 3, not the one made in step 1 (D-124c)", () => {
    // The flag reaches inside the release window because the key is bound to a
    // registered operator: a key that only exists signs reads the door answers
    // unregistered_operator. The old sentence said "step 1", which taught a
    // newcomer that generating a key was enough.
    const step = page.indexOf("Step 6. Verify it yourself");
    expect(step).toBeGreaterThan(-1);
    const panel = squeeze(page.slice(step));
    expect(panel).toContain(
      "signs the export's reads with the key you registered in step 3",
    );
    // The flag no longer reaches content: every entry is released at its seal
    // (D-127), so what it buys is the bucket the reads are counted in.
    expect(panel).toContain(
      "It is not what reaches the content",
    );
    expect(panel).toContain(
      "a signed read is metered under your operator rather than under the" +
        " address you came from",
    );
    expect(panel).not.toContain("the key you generated in step 1");
    // The export CLI never classifies the key, and it never refuses one: the
    // page may not promise a refusal word here.
    expect(
      squeeze(page.slice(page.indexOf("Step 6. Verify it yourself"))),
    ).not.toContain("unregistered_operator");
    expect(
      squeeze(page.slice(page.indexOf("Step 6. Verify it yourself"))),
    ).not.toContain("unregistered_operator");
  });

  it("links the draft list and says an underivable draft is not offered (D-124c)", () => {
    const step = page.indexOf("Step 4. Judge one entry");
    const panel = squeeze(page.slice(step, page.indexOf("Step 5.", step)));
    // The list is the naming, so the sentence stays true when the drafts change.
    expect(panel).toContain(
      `<a href="${LOCAL_DEMO_ORIGIN}/entries?status=draft"`,
    );
    expect(panel).toContain(
      "a draft the current schema cannot derive is not offered on it",
    );
    // Today's seeded draft is named as an example and said to be one.
    expect(panel).toContain("nmk_40ddff3c");
    expect(panel).toContain("take the list's word over this page's");
  });

  it("says what each stop reason means (D-124c)", () => {
    const step = page.indexOf("Step 4. Judge one entry");
    const panel = squeeze(page.slice(step, page.indexOf("Step 5.", step)));
    for (const reason of [
      "unregistered_operator",
      "legacy_entry",
      "schema_invalid",
      "entry_malformed",
    ]) {
      expect(panel, `${reason} is not explained`).toContain(
        `<span class="mono">${reason}</span>`,
      );
    }
    expect(panel).not.toContain("entry_withheld");
    expect(panel).toContain("Registration is step 3");
    expect(panel).toContain("cannot be judged under today's rules");
    expect(panel).toContain("errors</span> array is printed");
    // legacy_entry is the validate door's word alone: reconfirm, dispute and
    // revalidate still derive a pre-v0.7 entry into schema_invalid, so the page
    // may not teach schema_invalid as only ever the sender's own fault.
    expect(panel).toContain(
      "Validation is the only door that names it: reconfirm, dispute and" +
        " revalidate meet the same entry as a derivation that failed",
    );
    expect(panel).toContain(
      "on the three doors above it is also how a pre-v0.7 entry is refused",
    );
  });

  it("says what demo is not, and what the dry run that counts is", () => {
    expect(page).not.toContain("payout");
    expect(page).toContain("mock");
    expect(page).toContain("nothing on demo is money");
    expect(squeeze(page)).toContain("Nothing here is the record");
    expect(squeeze(page)).toContain(
      "the record is free to read from the seal, and the only thing anyone" +
        " earns for this work is standing",
    );
    expect(page).toContain("counts toward nothing");
  });

  it("links the genesis page and a way to reach a person", () => {
    // This environment's own genesis page, named as such, is the one relative
    // link the page keeps.
    expect(page).toContain(`href="/genesis"`);
    expect(page).toContain(`href="${LOCAL_DEMO_ORIGIN}/genesis"`);
    expect(page).toContain(`mailto:${CONTACT_EMAIL}`);
    expect(page).toContain("mailto:hello@nomankind.ai");
  });

  it("qualifies every link to where the dry run shows up, off demo", () => {
    // Read from production, a relative link would lead to a log holding none of
    // the run the commands just made on demo.
    const elsewhere = renderDryRun(productionCtx);
    expect(elsewhere).toContain(`href="${DEMO_ORIGIN}/genesis"`);
    // The mirror link in the body, not the footer's own relative one.
    expect(elsewhere).toContain(
      `<a href="${DEMO_ORIGIN}/mirror/latest">the mirror page</a>`,
    );
    expect(elsewhere).toContain(`${DEMO_ORIGIN}/operators/`);
    expect(elsewhere).toContain(`${DEMO_ORIGIN}/entries`);
    expect(elsewhere).toContain(`${DEMO_ORIGIN}/status`);
  });

  it("carries no script and no inline style", () => {
    expect(page).not.toContain("<script");
    expect(page).not.toContain(` style="`);
    const elsewhere = renderDryRun(productionCtx);
    expect(elsewhere).not.toContain("<script");
    expect(elsewhere).not.toContain(` style="`);
  });
});

/**
 * The Domains page: the registry's published tables, read out of the module the
 * kernel runs on.
 *
 * Every assertion below computes what it expects from src/policy.ts rather than
 * spelling it out, which is the whole point of the page: a window moved, a host
 * published or a category added by a later decision has to move this page with
 * it, and a test that had typed the old value would pass while the page lied.
 * The one thing the policy module does not hold is the copy, so the key set of
 * `DOMAIN_COPY` is pinned against `DOMAIN_SLUGS`: a domain registered later
 * arrives here with its own sentences or this file says so.
 */
describe("renderDomains", () => {
  const domainsCtx: PageContext = { ...ctx, path: "/domains" };

  /** A reading for every registered slug, as the route gathers it. */
  function reading(entries: number, trustedOperators: number): DomainsData {
    const counts: Record<
      string,
      { entries: number; trustedOperators: number }
    > = {};
    for (const slug of DOMAIN_SLUGS) counts[slug] = { entries, trustedOperators };
    return { counts };
  }

  const page = renderDomains(domainsCtx, reading(4, 3));

  /** One line of prose, however the template wrapped it. */
  function squeeze(rendered: string): string {
    return rendered.replace(/\s+/g, " ");
  }

  /** A sentence as the page had to escape it before writing it out. */
  function written(text: string): string {
    return squeeze(escapeHtml(text));
  }

  /** `90 days`, and `1 day` if a window ever were one. */
  function days(count: number): string {
    return count === 1 ? "1 day" : `${count} days`;
  }

  it("heads the page with the registry, the schema and how many there are", () => {
    expect(squeeze(page)).toContain(
      `registry v1 · schema ${SCHEMA_VERSION} · ${DOMAIN_SLUGS.length} registered`,
    );
    expect(squeeze(page)).toContain(
      "A domain is a subject area the log records. The mechanism is the same in" +
        " every one: a claim, a citation, a snapshot hash, and the signatures of" +
        " operators no interested party controls.",
    );
    expect(squeeze(page)).toContain(
      "Every entry names its domain in its signed core, so a fact can never be" +
        " moved from one domain to another, by anyone.",
    );
  });

  it("gives every registered domain a strip cell and a panel of its own", () => {
    for (const slug of DOMAIN_SLUGS) {
      const copy = DOMAIN_COPY[slug];
      expect(copy, `${slug} has no copy`).toBeDefined();
      expect(page, `${slug} has no anchor in the strip`).toContain(
        `href="#${slug}"`,
      );
      expect(page, `${slug} has no panel`).toContain(
        `<section class="panel" id="${slug}">`,
      );
      expect(squeeze(page)).toContain(domainPolicy(slug).name);
      expect(squeeze(page)).toContain(`<span class="mono dim">${slug}</span>`);
      expect(squeeze(page)).toContain(written(copy!.short_line));
      expect(squeeze(page)).toContain(written(copy!.what));
      expect(squeeze(page)).toContain(written(copy!.who_validates));
    }
  });

  it("badges every category the domain admits", () => {
    for (const slug of DOMAIN_SLUGS) {
      for (const category of domainPolicy(slug).categories) {
        expect(page, `${slug} does not badge ${category}`).toContain(
          `<span class="badge ">${category}</span>`,
        );
      }
    }
  });

  it("carries the attestation sentence and its version verbatim", () => {
    for (const slug of DOMAIN_SLUGS) {
      const attestation = attestationFor(slug);
      expect(squeeze(page)).toContain(written(attestation.text));
      expect(page).toContain(attestation.version);
    }
  });

  it("computes the freshness line from the windows, and names the rest", () => {
    for (const slug of DOMAIN_SLUGS) {
      const never: string[] = [];
      for (const category of domainPolicy(slug).categories) {
        const window = stalenessWindowDays(slug, category);
        if (window === null) never.push(category);
        else
          expect(
            squeeze(page),
            `${slug}/${category} is not shown with its window`,
          ).toContain(`${category} ${days(window)}`);
      }
      if (never.length > 0) {
        expect(squeeze(page)).toContain(
          `The rest never go stale: ${never.join(", ")}.`,
        );
      }
    }
  });

  it("says which categories carry a transcript, and what the others carry", () => {
    for (const slug of DOMAIN_SLUGS) {
      const transcripts = domainPolicy(slug).transcript_categories;
      expect(squeeze(page)).toContain(
        transcripts.length === 0 ? "none —" : `${transcripts.join(", ")} —`,
      );
      expect(squeeze(page)).toContain(
        written(DOMAIN_COPY[slug]!.transcript_note),
      );
    }
  });

  it("counts the excluded parties and names the first of them", () => {
    for (const slug of DOMAIN_SLUGS) {
      const hosts = excludedPartyDomains(slug);
      expect(squeeze(page)).toContain(`${hosts.length} parties`);
      for (const host of hosts.slice(0, 7)) {
        expect(page, `${host} is not named`).toContain(host);
      }
      expect(squeeze(page)).toContain(
        `<a href="/policy">the rest on the policy page</a>`,
      );
    }
  });

  it("names the categories that must cite an official source", () => {
    for (const slug of DOMAIN_SLUGS) {
      for (const category of domainPolicy(slug).sources.official_required) {
        expect(page, `${category} is not named as official-required`).toContain(
          `<span class="badge ">${category}</span>`,
        );
      }
      expect(squeeze(page)).toContain(
        "Every other category may cite any host, and the citation is labeled" +
          " official, recognized, or other.",
      );
    }
  });

  it("shows how a subject is named, and the read call that follows from it", () => {
    for (const slug of DOMAIN_SLUGS) {
      const policy = domainPolicy(slug);
      const copy = DOMAIN_COPY[slug]!;
      expect(squeeze(page)).toContain(escapeHtml(policy.subject_convention));
      expect(page).toContain(
        `GET /read?domain=${slug}&amp;subject=${copy.subject_example}` +
          `&amp;category=${policy.categories[0]}`,
      );
    }
  });

  it("shows this log's own two counters, and the three ways in", () => {
    for (const slug of DOMAIN_SLUGS) {
      expect(squeeze(page)).toContain(`>4 entries</a`);
      expect(squeeze(page)).toContain(`>3 trusted operators</a`);
      expect(squeeze(page)).toContain(
        `<a class="btn btn-accent" href="/entries?domain=${slug}"` +
          ` >Browse entries</a`,
      );
      expect(page).toContain(`<a class="btn" href="/policy">Policy tables</a>`);
      expect(page).toContain(
        `<a class="btn" href="/genesis">Join this domain</a>`,
      );
    }
    // One entry and one operator, said as one and not as "1 entrys".
    const one = renderDomains(domainsCtx, reading(1, 1));
    expect(squeeze(one)).toContain(">1 entry</a");
    expect(squeeze(one)).toContain(">1 trusted operator</a");
  });

  it("reads registered with no trusted operator, and recruited with one", () => {
    const empty = renderDomains(domainsCtx, reading(0, 0));
    expect(empty).toContain(`<span class="badge s-draft">registered</span>`);
    expect(empty).not.toContain("recruited");
    expect(empty).toContain("0 entries");

    const recruited = renderDomains(domainsCtx, reading(0, 1));
    expect(recruited).toContain(
      `<span class="badge s-verified">recruited</span>`,
    );
    expect(recruited).not.toContain(">registered<");
  });

  it("says how a domain is added, without making it a code change", () => {
    expect(page).toContain(`<h2 class="panel-title">Adding a domain</h2>`);
    expect(squeeze(page)).toContain(
      "A new domain is a published decision, not a code change: its tables are" +
        " written into the registry first, its slug is added to the schema, and" +
        " the policy module is extended to match, pinned by a test so the two" +
        " never drift.",
    );
    expect(squeeze(page)).toContain(
      "Operators join a later domain by signing that domain's attestation, a" +
        " public event in the log.",
    );
  });

  it("shows the disclosure rule and the version rule where policy has them", () => {
    // Decision D-096. Both are optional, and the page reads them off the domain
    // rather than naming a category or a window of its own: a domain that
    // publishes neither shows neither row, and a domain that publishes one
    // shows its categories badged and its window in days.
    const count = (needle: string): number =>
      page.split(needle).length - 1;
    const withDisclosure = DOMAIN_SLUGS.filter(
      (slug) => domainPolicy(slug).disclosure !== undefined,
    );
    const withVersions = DOMAIN_SLUGS.filter(
      (slug) => domainPolicy(slug).version_staleness !== undefined,
    );
    expect(count("<dt>Delayed disclosure</dt>")).toBe(withDisclosure.length);
    expect(count("<dt>Staleness on a version change</dt>")).toBe(
      withVersions.length,
    );

    for (const slug of withDisclosure) {
      const rule = domainPolicy(slug).disclosure!;
      for (const category of rule.categories) {
        expect(page, `${slug}/${category} is not badged`).toContain(
          `<span class="badge ">${category}</span>`,
        );
      }
      expect(squeeze(page)).toContain(
        `published ${days(rule.window_days)} after it`,
      );
    }
    for (const slug of withVersions) {
      for (const category of domainPolicy(slug).version_staleness!.categories) {
        expect(page, `${slug}/${category} is not badged`).toContain(
          `<span class="badge ">${category}</span>`,
        );
      }
    }
  });

  it("carries copy for exactly the registered domains, and no others", () => {
    expect([...Object.keys(DOMAIN_COPY)].sort()).toEqual(
      [...DOMAIN_SLUGS].sort(),
    );
  });

  it("carries no script and no inline style", () => {
    expect(page).not.toContain("<script");
    expect(page).not.toContain(` style="`);
  });
});

describe("renderLanding", () => {
  /**
   * A hand-made reading, not a fixture off the store: the page's job is to print
   * what it was handed, so the data says what every assertion below expects to
   * see, down to a hash that is markup if nothing escapes it.
   */
  const data: LandingData = {
    seals: [
      {
        seq: 0,
        hash: "sha256:a61ae671cdb6f0e4b7dd6a3e6a1d7d4f0d1c2b3a49586776655443322110099a",
        sealedAt: "2026-09-09T17:47:27.000Z",
        witnessed: true,
        events: 4,
      },
      {
        seq: 1,
        hash: "sha256:3eb4ad8a83b512c9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071",
        sealedAt: "2026-09-09T17:52:31.000Z",
        witnessed: true,
        events: 2,
      },
      {
        seq: 2,
        hash: "sha256:92fe03dab291<b>0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778",
        sealedAt: "2026-09-09T17:57:30.000Z",
        witnessed: false,
        events: 1,
      },
    ],
    sealCount: 288,
    verified: 41,
    witnesses: 3,
  };
  const page = renderLanding(ctx, data);

  it("is a whole document of its own with the landing stylesheet", () => {
    expect(page.startsWith("<!doctype html>")).toBe(true);
    expect(page).toContain(`<html lang="en">`);
    // D-114: the title says what the record is, not only what it is called. A
    // search result and a shared link show this line first, and the bare
    // wordmark told a first-time reader nothing.
    expect(page).toContain(
      "<title>nomankind: verified facts for models that keep learning</title>",
    );
    expect(page).toContain(`href="${LANDING_CSS_HREF}"`);
    expect(LANDING_CSS_HREF.startsWith("/static/landing.css?v=")).toBe(true);
    expect(page).toContain("fonts.googleapis.com");
  });

  it("leads with the hero line and the primary use case", () => {
    expect(page).toContain("Proof-of-provenance.");
    expect(page).toContain("Proof-of-truth.");
    expect(page).toContain("VERIFIED FACTS FOR MODELS THAT KEEP LEARNING");
    expect(page).toContain("neutral trust substrate");
    expect(page).not.toContain("where it cannot, the feed says so");
    expect(page).toContain("Nothing enters the feed until its source is");
  });

  it("names the three cards", () => {
    expect(page).toContain("FOR MODELS THAT KEEP LEARNING");
    expect(page).toContain("PROOF-OF-PROVENANCE");
    expect(page).toContain("PROOF-OF-TRUTH");
  });

  it("names the domains it reaches next, as labels and not links", () => {
    expect(page).toContain("WHERE IT REACHES NEXT");
    for (const domain of [
      "ENTERPRISE COMPLIANCE",
      "REGULATED INDUSTRIES",
      "SCIENTIFIC AI",
      "LEGAL AI",
      "MEDICAL AI",
      "FINANCIAL AI",
    ]) {
      expect(page).toContain(`class="reach-tag mono">${domain}<`);
    }
  });

  it("holds the five values", () => {
    expect(page).toContain("Owned by no lab.");
    expect(page).toContain("Facts, never opinions.");
    expect(page).toContain("Credited for being right.");
    expect(page).toContain("Checkable offline.");
    expect(page).toContain("Forkable.");
  });

  // Both doors are still on the page; where each one leads depends on the
  // environment, which the test below this describe's data holds to.
  it("offers both doors", () => {
    expect(page).toContain(`class="btn-primary"`);
    expect(page).toContain(`class="btn-ghost"`);
    expect(page).toContain("Open the app");
    expect(page).toContain("Try the demo");
  });

  it("links the paper, the code, the mirror and the registry", () => {
    // D-104: the paper is a page of this site now, so the top bar's Whitepaper
    // link is relative exactly as Domains is, and the GitHub blob URL is gone.
    expect(page).toContain(`<a href="/docs/whitepaper">Whitepaper</a>`);
    expect(page).not.toContain(
      "https://github.com/nomankind-ai/nomankind/blob/main/paper/WHITEPAPER.md",
    );
    expect(page).toContain(`href="https://github.com/nomankind-ai/nomankind"`);
    expect(page).toContain(`href="https://github.com/nomankind-ai/log"`);
    expect(page).toContain(`href="https://1f916.org"`);
  });

  /**
   * The top bar's first link is the one page on this site the reader has not
   * seen yet, and it is the only link in that nav that stays on this origin: on
   * the apex every path but `/` is the app, so /how-it-works is nomankind.ai's
   * own page, and on demo the same relative href is demo's. Being same-origin
   * is what it means for it to carry no `rel` where the four outbound links
   * carry `rel="noopener"` — a relative href with a rel would be the tell that
   * someone had copied one of the outbound anchors without reading it.
   */
  it("leads the top bar with How it works, before the whitepaper", () => {
    const nav = page.slice(
      page.indexOf(`<nav class="topnav">`),
      page.indexOf("</nav>"),
    );
    expect(nav).toContain(`<a href="/how-it-works">How it works</a>`);
    expect(nav.indexOf("/how-it-works")).toBeLessThan(nav.indexOf("Whitepaper"));
    expect(nav).not.toMatch(/<a href="\/how-it-works"[^>]*rel=/);
    // The registry is the second of the two same-origin links, right after it,
    // and it carries no rel for the same reason: it is this site's own page.
    expect(nav).toContain(`<a href="/domains">Domains</a>`);
    expect(nav.indexOf("/how-it-works")).toBeLessThan(nav.indexOf("/domains"));
    expect(nav.indexOf("/domains")).toBeLessThan(nav.indexOf("Whitepaper"));
    expect(nav).not.toMatch(/<a href="\/domains"[^>]*rel=/);
    // The whitepaper joined them: it is served from this origin too (D-104),
    // so it is the third same-origin link and carries no rel either.
    expect(nav).not.toMatch(/<a href="\/docs\/whitepaper"[^>]*rel=/);
    // And it is a link out of the page, not a script or a style that the
    // content-security-policy would drop on the floor.
    expect(page).not.toContain("<script");
    expect(page).not.toContain("style=");
  });

  it("draws the proof pipeline inline, from the source to the learner", () => {
    expect(page).toContain("<svg");
    const svg = page.slice(page.indexOf("<svg"), page.indexOf("</svg>"));
    expect(svg).toContain("Source");
    expect(svg).toContain("Snapshot");
    expect(svg).toContain("Seal");
    expect(svg).toContain("Learner");
  });

  it("shows the seal chain it was handed, witnessed or pending", () => {
    for (const seal of data.seals) {
      expect(page).toContain(shortHash(seal.hash));
      expect(page).toContain(`#${seal.seq}`);
    }
    expect(page).toContain("witnessed");
    expect(page).toContain("pending");
    expect(page).toContain("SEAL CHAIN · LIVE");
  });

  it("prints the three numerals off the log, and nothing of its own", () => {
    expect(page).toContain(">288<");
    expect(page).toContain(">3<");
    expect(page).toContain(">41<");
    expect(page).toContain("SEALS");
    expect(page).toContain("INDEPENDENT WITNESSES");
    expect(page).toContain("VERIFIED FACTS");
    expect(page).toContain("one every five minutes, each countersigned");
    expect(page).toContain("none owned by a model provider");
    expect(page).toContain("checked by three operators, sealed, dated");
  });

  it("says so in words when nothing is sealed yet", () => {
    const fresh = renderLanding(ctx, {
      seals: [],
      sealCount: 0,
      verified: 0,
      witnesses: 3,
    });
    expect(fresh).toContain("no seal yet");
    expect(fresh).toContain("band-still");
    expect(fresh).not.toContain("band-witnessed");
    expect(fresh).not.toContain("band-pending");
  });

  it("closes on the two tiers and the licence line", () => {
    expect(page).toContain("Claims you can trace.");
    expect(page).toContain("<em>Truths that held.</em>");
    // The maintainer's words, 2026-09-11: claims and truths, not quotations and
    // measurements. The old pair is gone from the page, not merely joined.
    expect(page).not.toContain("Quotations");
    expect(page).not.toContain("Measurements");
    // The maintainer's words, as decision D-127 left them: the data is CC0 from
    // the seal that covers it, and training on it is free, full stop. The
    // three-part shape is kept and the waiting is gone.
    expect(page).toContain(
      "CODE APACHE-2.0 · DATA CC0 FROM THE SEAL · TRAINING ON THE DATA IS FREE",
    );
    expect(page).not.toContain("ON RELEASE");
    // And the one other sentence that called the data free says the same.
    expect(page).toContain("public-domain data from the seal");
  });

  it("survives the content-security-policy: no script, no inline style", () => {
    expect(page).not.toContain("<script");
    expect(page).not.toContain("style=");
    expect(page).not.toContain("javascript:");
    // And the same of an app page, which is drawn by the shared layout: both
    // halves of this UI are server-rendered markup the CSP can allow whole.
    const app = renderPolicy(ctx, POLICY);
    expect(app).not.toContain("<script");
    expect(app).not.toContain(' style="');
  });

  /**
   * The top bar's wordmark is a link home like the app header's, and home is
   * the apex — the landing is served from the apex root, but also from demo and
   * from a local Worker, where a reader clicking it means nomankind.ai.
   */
  it("links its top bar wordmark to the apex", () => {
    expect(page).toContain(
      `<a class="wordmark mono" href="${APEX_URL}">NOMANKIND</a>`,
    );
    expect(page).not.toContain(`<span class="wordmark mono">`);
  });

  /**
   * D-085: one free way to reach a person, with no account and no form — the
   * last link in the top bar, and again in the footer beside the wordmark. A
   * mailto, so there is nothing to sign up for and nothing to host; the href
   * keeps the address as it is typed and the footer prints it in the page's own
   * mono uppercase.
   */
  it("offers a contact address in the top bar and in the footer", () => {
    expect(CONTACT_EMAIL).toBe("hello@nomankind.ai");
    const nav = page.slice(
      page.indexOf(`<nav class="topnav">`),
      page.indexOf("</nav>"),
    );
    expect(nav).toContain(`<a href="mailto:${CONTACT_EMAIL}">Contact</a>`);
    expect(nav.indexOf("Built on 1F916")).toBeLessThan(nav.indexOf(">Contact<"));
    expect(nav.lastIndexOf("<a ")).toBe(nav.indexOf(`<a href="mailto:`));
    expect(nav.slice(nav.indexOf(`<a href="mailto:`))).not.toContain("rel=");

    const footer = page.slice(page.indexOf(`<footer class="landing-footer`));
    expect(footer).toContain("NOMANKIND.AI ·");
    expect(footer).toContain(
      `<a href="mailto:${CONTACT_EMAIL}">HELLO@NOMANKIND.AI</a>`,
    );
    // Still the page the CSP can serve whole: a mailto is a navigation, not a
    // load, so nothing here is script and nothing here is an inline style.
    expect(page).not.toContain("<script");
    expect(page).not.toContain("style=");
  });

  it("escapes a seal hash that is markup", () => {
    expect(page).not.toContain("<b>");
    expect(page).toContain("&lt;b&gt;");
  });

  /**
   * D-064. The two buttons used to name app.nomankind.ai and demo.nomankind.ai
   * in every environment, so the front door of a local Worker or of demo sent a
   * reader to production. The app button now points at whatever deployment is
   * serving the page unless that deployment is production, where the landing is
   * the apex and the app really is another host; the demo button points at demo
   * from everywhere except demo, which is already there.
   */
  it("points its buttons at the environment the page is being read on", () => {
    const on = (environment: string): string =>
      renderLanding({ ...ctx, environment, path: "/" }, data);

    const demo = on("demo");
    expect(demo).toContain(`<a class="btn-primary" href="/">`);
    expect(demo).toContain(`<a class="btn-ghost" href="/entries">`);

    const local = on("local");
    expect(local).toContain(`<a class="btn-primary" href="/">`);
    expect(local).toContain(
      `<a class="btn-ghost" href="https://demo.nomankind.ai/">`,
    );

    const production = on("production");
    expect(production).toContain(
      `<a class="btn-primary" href="https://app.nomankind.ai/">`,
    );
    expect(production).toContain(
      `<a class="btn-ghost" href="https://demo.nomankind.ai/">`,
    );
  });
});

describe("LANDING_CSS", () => {
  it("is the landing page's whole look, in one string", () => {
    expect(LANDING_CSS.length).toBeGreaterThan(0);
    expect(LANDING_CSS).toContain("Space Grotesk");
    expect(LANDING_CSS).toContain("JetBrains Mono");
    expect(LANDING_CSS).not.toContain("Instrument Serif");
    expect(LANDING_CSS).not.toContain("Manrope");
  });

  it("stops every motion under prefers-reduced-motion", () => {
    expect(LANDING_CSS).toContain("prefers-reduced-motion");
  });

  it("stacks the grids on a narrow viewport", () => {
    expect(LANDING_CSS).toContain("@media (max-width: 900px)");
  });
});

/**
 * The two spec files, read as files (decision D-087).
 *
 * A page can be made to say anything the test asks for. The paper and the
 * README are the documents the pages are checked against, so the rule that
 * observed entries pay more has to be in them, labeled, and in the section it
 * belongs to — beside the sentence it makes precise and not appended somewhere
 * a reader of that sentence would never reach it.
 */
const whitepaper = readFileSync(
  fileURLToPath(new URL("../paper/WHITEPAPER.md", import.meta.url)),
  "utf8",
);
const readme = readFileSync(
  fileURLToPath(new URL("../README.md", import.meta.url)),
  "utf8",
);

describe("the paper and the README carry observed pays more (D-087)", () => {
  it("states the money side in Section 9, after the promise it makes precise", () => {
    const promise = whitepaper.indexOf(
      "paid more than the operators who copy (Section 4).",
    );
    const addition = whitepaper.indexOf(
      "The split is published per evidence tier",
    );
    expect(promise).toBeGreaterThan(-1);
    expect(addition).toBeGreaterThan(promise);
    expect(whitepaper).toContain("READ_SHARE_SPLIT in the policy module");
    expect(whitepaper).toContain("the tier is the one fixed when the entry verified");
    expect(whitepaper).toContain(
      "only when its own signed record carries a passing measurement",
    );
    expect(whitepaper).toContain(
      "a validator who accepted the test without running it is paid at the stated rate",
    );
    expect(whitepaper).toContain("rather than moving the reader's price");
  });

  it("states the standing side in Section 4, beside the tier sentence", () => {
    const tiers = whitepaper.indexOf("is paid more for it (Section 9)");
    const standing = whitepaper.indexOf(
      "The standing side of the same rule is STANDING_VALIDATION_REPRODUCED",
    );
    const money = whitepaper.indexOf(
      "The split is published per evidence tier",
    );
    expect(tiers).toBeGreaterThan(-1);
    expect(standing).toBeGreaterThan(tiers);
    // Section 4 comes before Section 9, so the standing sentence comes first:
    // a paragraph landing in the wrong section would still contain the words.
    expect(standing).toBeLessThan(money);
    expect(whitepaper).toContain(
      "earns it beside the assigned or volunteered amount",
    );
  });

  it("states the changed-check reward in Section 6, beside the promise (D-095)", () => {
    const promise = whitepaper.indexOf("plus a challenger-style reward.");
    const labeled = whitepaper.indexOf("The reward is paid in standing");
    expect(promise).toBeGreaterThan(-1);
    expect(labeled).toBeGreaterThan(promise);
    expect(whitepaper).toContain("STANDING_REVALIDATION_CHANGED");
    expect(whitepaper).toContain("the currency the stake was in");
    expect(whitepaper).toContain(
      "a dispute's reward is money because a dispute claws money back",
    );
    // The README says it too, in the section that names the stake. It is one
    // currency there now (D-127), so the reward is named where the rest of the
    // fold is rather than under a heading of its own.
    const section = readme.indexOf("## Standing and contribution");
    const rule = readme.indexOf("`STANDING_REVALIDATION_CHANGED` (D-095)");
    const next = readme.indexOf("## Attesting a model");
    expect(section).toBeGreaterThan(-1);
    expect(rule).toBeGreaterThan(section);
    expect(rule).toBeLessThan(next);
  });

  it("names the rule in the README, in the section about contribution", () => {
    // D-087's promise, in the currency D-127 left: measuring earns more
    // standing, and nobody is paid more because nobody is paid.
    const section = readme.indexOf("## Standing and contribution");
    const rule = readme.indexOf("**Measuring earns more than copying**");
    const next = readme.indexOf("## Attesting a model");
    expect(section).toBeGreaterThan(-1);
    expect(rule).toBeGreaterThan(section);
    expect(rule).toBeLessThan(next);
    expect(readme).toContain("`STANDING_VALIDATION_REPRODUCED`");
    expect(readme).toContain("carries a passing measurement under the n-of-k rule");
    expect(readme).toContain("nobody is paid more, because nobody is paid");
    expect(readme).not.toContain("`READ_SHARE_SPLIT.observed`");
  });
});

// ---------------------------------------------------------------------------
// The release window on the documentation pages (decision D-100)
// ---------------------------------------------------------------------------

describe("the release window, as the pages publish it", () => {
  const policy = renderPolicy(ctx, POLICY);
  const api = renderApi(ctx);
  const domains = renderDomains({ ...ctx, path: "/domains" }, DOMAINS_READING);

  it("publishes the window as a number the page read from policy", () => {
    expect(policy).toContain(`<td class="mono">RELEASE_WINDOW_DAYS</td>`);
    expect(policy).toContain(
      `<td class="mono">${POLICY.RELEASE_WINDOW_DAYS} days</td>`,
    );
    // In its own Release group, where the money group used to be: the window
    // prices nothing any more, it says when the record opens (D-127).
    const release = policy.indexOf(">Release</h2>");
    const access = policy.indexOf(">Access and alerts</h2>");
    expect(release).toBeGreaterThan(-1);
    expect(policy.indexOf("RELEASE_WINDOW_DAYS")).toBeGreaterThan(release);
    expect(policy.indexOf("RELEASE_WINDOW_DAYS")).toBeLessThan(access);
  });

  it("names no door the window holds back, because at zero it holds none", () => {
    // The doors the window used to change say what they do now: the same record
    // to everybody, with no 402, no released head and no hash line (D-127).
    for (const gone of [
      "402 unreleased with release_date",
      "served to the released head rather than the sealed",
      "{ proof, release_date }",
      "goes to a free reader as a hash line",
      "403 unreleased, carrying release_date",
    ]) {
      expect([gone, api.includes(gone)]).toEqual([gone, false]);
    }
    expect(api).toContain("the content is public and CC0 from the seal");
    expect(api).toContain("Every event goes out in full the moment a seal covers it");
    expect(api).toContain("head and sealed_head name the same position");
  });

  it("explains the rule once, under the keys section, and links it", () => {
    expect(api).toContain(`<section class="panel" id="keys">`);
    const keys = api.indexOf(`id="keys"`);
    const rule = api.indexOf("The record is free (decision D-127).");
    expect(rule).toBeGreaterThan(keys);
    expect(api).toContain("answer the same record to");
    expect(api).toContain("the record is free from the seal");
  });

  it("names the flag that reaches unreleased content from a command", () => {
    expect(api).toContain("--sign &lt;key.json&gt;");
    expect(api.replace(/\s+/g, " ")).toContain(
      "signs the export's reads with an operator's agent key",
    );
  });

  it("says in the Domains lede that the record is free from the seal", () => {
    expect(domains.replace(/\s+/g, " ")).toContain(
      "its content is public and CC0 the moment it is sealed, with nothing to pay and no key to hold (decisions D-100 and D-127)",
    );
  });

  it("adds no script and no inline style to any of them", () => {
    for (const document of [policy, api, domains]) {
      expect(document).not.toContain("<script");
      expect(document).not.toContain(' style="');
    }
  });
});

/**
 * The documentation hub and the three documents it serves (D-104).
 *
 * Before this page the answer to "where is this written down" was a list
 * somebody had to know, and two of the documents were only on GitHub. The hub
 * is that list, and the assertions below are the mockup the maintainer
 * approved: three groups, twelve cards, every card a page this Worker serves.
 */
describe("renderDocs", () => {
  const docsCtx: PageContext = { ...ctx, path: "/docs" };
  const page = renderDocs(docsCtx);
  const flat = page.replace(/\s+/g, " ");

  it("heads the page with the versions it is a reading of, from policy", () => {
    expect(page).toContain("<h1>Docs</h1>");
    expect(flat).toContain(
      `whitepaper ${WHITEPAPER_VERSION} · schema ` +
        `${SCHEMA_VERSION} · ${POLICY.NORM_VERSION}`,
    );
    // One constant, named in src/ui/pages/document.ts beside the document it is
    // the version of: the hub's head line, its whitepaper card, the document
    // page's note and the how-it-works head line all read it.
    expect(WHITEPAPER_VERSION).toBe("v1.6");
    expect(WHITEPAPER_DOCUMENT.note).toContain(WHITEPAPER_VERSION);
  });

  it("carries the lede the decision wrote", () => {
    expect(flat).toContain(
      "Everything written about the record, in one place. The pages under Read " +
        "the record describe what the log is; Join is how an operator gets in; " +
        "Take it with you is how anyone leaves with the whole thing. The " +
        "whitepaper and the summary are served here too, so nothing about the " +
        "design lives only on GitHub.",
    );
  });

  it("groups the twelve cards in three panels, each with its own line", () => {
    expect(DOC_GROUPS.map((each) => each.title)).toEqual([
      "Read the record",
      "Join",
      "Take it with you",
    ]);
    expect(DOC_GROUPS.flatMap((each) => each.cards)).toHaveLength(12);
    expect(flat).toContain(
      `<span class="stage-num">01</span>Read the record </h2> ` +
        `<span class="note">What the log is and how to read it.</span>`,
    );
    expect(flat).toContain(
      `<span class="stage-num">02</span>Join </h2> ` +
        `<span class="note">How an operator gets in, and how to practise first.</span>`,
    );
    expect(flat).toContain(
      `<span class="stage-num">03</span>Take it with you </h2> ` +
        `<span class="note">The exit is a copy, not a promise.</span>`,
    );
  });

  it("draws every card as a link with its one line", () => {
    const expected: readonly (readonly [string, string, string])[] = [
      [
        "/how-it-works",
        "How it works",
        "The pipeline in ten stages, each linked into this environment's own log.",
      ],
      [
        "/domains",
        "Domains",
        "The three registered domains: what each records, who reads it, who validates it.",
      ],
      [
        "/policy",
        "Policy",
        "Every published number, list, and sentence the rules run on, from the policy module.",
      ],
      [
        "/api",
        "API",
        "Every door: reading with receipts, syncing the delta, keys and tiers, and the refusals.",
      ],
      [
        "/independence",
        "Independence",
        "The validator set and the pinned witness set side by side, their intersection, and what object each signature covers.",
      ],
      [
        "/genesis",
        "Genesis",
        "The three joining steps, the attestation, and the dry-run table read from the log.",
      ],
      [
        "/dry-run",
        "Dry run",
        "Practise the joining steps and one validation on demo, command by command.",
      ],
      [
        "/operators",
        "Operators",
        "The directory: who is trusted, in which domains, with what standing.",
      ],
      [
        "/docs/fork",
        "Fork guide",
        "What to clone, how to verify a mirror, and how to keep going without nomankind.",
      ],
      [
        "/mirror/latest",
        "Mirror",
        "The daily export of the sealed log under CC0, and the pointer to today's.",
      ],
      [
        "/docs/whitepaper",
        "Whitepaper",
        `The specification, consolidated at ${WHITEPAPER_VERSION}.`,
      ],
      ["/docs/summary", "Summary", "The whitepaper in one page."],
    ];
    expect(DOC_GROUPS.flatMap((each) => each.cards).map((each) => [each.href, each.title, each.line])).toEqual(
      expected.map((each) => [...each]),
    );
    for (const [href, title, line] of expected) {
      expect(flat).toContain(
        `<a class="step" href="${href}" ><span class="step-t">${title}</span> ` +
          `<span class="note">${escapeHtml(line)}</span></a >`,
      );
    }
  });

  it("marks Docs active and carries no script and no inline style", () => {
    expect(page).toContain(`<a class="nav nav-active" href="/docs">Docs</a>`);
    expect(page).not.toContain("<script");
    expect(page).not.toContain(' style="');
  });
});

describe("renderDocument", () => {
  const documents = [
    { path: "/docs/fork", data: FORK_DOCUMENT },
    { path: "/docs/whitepaper", data: WHITEPAPER_DOCUMENT },
    { path: "/docs/summary", data: SUMMARY_DOCUMENT },
  ];

  it("titles the three documents as the decision names them", () => {
    expect(documents.map((each) => each.data.title)).toEqual([
      "Forking nomankind",
      "Whitepaper",
      "Summary",
    ]);
  });

  for (const document of documents) {
    const page = renderDocument({ ...ctx, path: document.path }, document.data);
    const flat = page.replace(/\s+/g, " ");

    it(`crumbs, heads and names the source of ${document.path}`, () => {
      expect(flat).toContain(
        `<div class="crumbs mono"> <a href="/docs">Docs</a><span>/</span>` +
          `<span>${escapeHtml(document.data.title)}</span> </div>`,
      );
      expect(page).toContain(`<h1>${escapeHtml(document.data.title)}</h1>`);
      expect(flat).toContain(
        `${document.data.note} · <span class="mono">${document.data.sourcePath}</span>`,
      );
    });

    it(`strips every top-level section of ${document.path} as an anchor`, () => {
      const top = sections(document.data.markdown);
      expect(top.length).toBeGreaterThan(2);
      // Auto-fit columns, as the Domains strip does: five sections and thirteen
      // both lay out, which a fixed column count could not do for both.
      expect(page).toContain(`<div class="counters">`);
      top.forEach((heading, index) => {
        const number = String(index + 1).padStart(2, "0");
        expect(flat).toContain(
          `<a class="step" href="#${heading.id}" ><span class="step-n">${number}</span ` +
            `><span class="step-t">${escapeHtml(heading.text)}</span></a >`,
        );
        expect(page).toContain(`id="${heading.id}"`);
      });
      // And nothing else: the strip is the document's sections, not a second
      // copy of its table of contents.
      expect(page.match(/<a class="step"/g)).toHaveLength(top.length);
    });

    it(`prints one h1 on ${document.path}, and the document's headings under it`, () => {
      // The page has a title of its own, so the document's opening title is
      // dropped and everything under it is one level down.
      expect(page.match(/<h1/g)).toHaveLength(1);
      expect(page).toContain(`<h1>${escapeHtml(document.data.title)}</h1>`);
      const first = headings(document.data.markdown)[0];
      expect(first?.level).toBe(1);
      expect(page).not.toContain(`<h1 id="${first?.id}"`);
      // The fork guide's own title is the page's, so it is printed once: the
      // page's <h1> and nothing under it saying the same thing again.
      if (first?.text === document.data.title) {
        expect(page).not.toContain(`id="${first.id}"`);
        const body = page.slice(page.indexOf(`class="panel-body document"`));
        expect(body).not.toContain(escapeHtml(first.text));
      }
      for (const section of sections(document.data.markdown)) {
        // One level down from what the source writes: the whitepaper's level-1
        // sections are h2 here, the fork guide's and the summary's level-2
        // sections are h3.
        const tag = section.level === 1 ? "h2" : "h3";
        expect(page, `${section.id} is not an ${tag}`).toContain(
          `<${tag} id="${section.id}">`,
        );
      }
    });

    it(`renders ${document.path} inside one panel, under the policy`, () => {
      expect(flat).toContain(
        `<section class="panel"> <div class="panel-body document">`,
      );
      expect(page).not.toContain("<script");
      expect(page).not.toContain(' style="');
      expect(page).toContain(`<a class="nav nav-active" href="/docs">Docs</a>`);
    });
  }

  it("strips the whitepaper's own thirteen sections, not its subsections", () => {
    // The paper writes its sections at level one under a level-one title, so a
    // strip of its level-2 headings would list fifteen subsections and none of
    // the sections a reader is looking for.
    const top = sections(WHITEPAPER_DOCUMENT.markdown);
    expect(top).toHaveLength(13);
    expect(top.map((each) => each.text)).toEqual([
      "Introduction",
      "Goals and non-goals",
      "The log",
      "Evidence",
      "Identity and operators",
      "Lifecycle of an entry",
      "Freshness and decay",
      "The training path",
      "Incentives",
      "Governance and legal posture",
      "Deployment and status",
      "Limitations",
      "Conclusion",
    ]);
    const flat = renderDocument(
      { ...ctx, path: "/docs/whitepaper" },
      WHITEPAPER_DOCUMENT,
    ).replace(/\s+/g, " ");
    expect(flat).toContain(
      `<span class="step-n">01</span ><span class="step-t">Introduction</span>`,
    );
    expect(flat).toContain(
      `<span class="step-n">13</span ><span class="step-t">Conclusion</span>`,
    );
  });

  it("strips the fork guide's level-2 sections, its title being its only level-1", () => {
    const top = sections(FORK_DOCUMENT.markdown);
    expect(top.every((each) => each.level === 2)).toBe(true);
    expect(top).toEqual(
      headings(FORK_DOCUMENT.markdown).filter((each) => each.level === 2),
    );
  });
});

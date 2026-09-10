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
import { ANSWER_REFUSALS, SCORE_REFUSALS } from "../src/attest.js";
import { CORE_KEYS } from "../src/core.js";
import {
  DEFAULT_DOMAIN,
  DOMAINS,
  LIST_PAGE_LIMIT,
  POLICY,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
} from "../src/policy.js";
import {
  ATTESTATION_TEXT,
  ATTESTATION_VERSION,
  JOIN_REFUSALS,
  TXT_RECORD_PREFIX,
} from "../src/registry.js";
import { READ_QUERY_REFUSALS } from "../src/read.js";
import { SUBMISSION_REFUSALS } from "../src/submit.js";
import { SYNC_QUERY_REFUSALS } from "../src/sync.js";
import { renderApi } from "../src/ui/pages/api.js";
import { VALIDATION_REFUSALS } from "../src/validate.js";
import { renderGenesis } from "../src/ui/pages/genesis.js";
import { shortHash } from "../src/ui/html.js";
import {
  LANDING_CSS,
  LANDING_CSS_HREF,
  renderLanding,
} from "../src/ui/pages/landing.js";
import { renderPolicy } from "../src/ui/pages/policy.js";
import type {
  GenesisData,
  LandingData,
  PageContext,
} from "../src/ui/types.js";

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

  it("says plainly that there is no seed fee (D-052)", () => {
    expect(page).toContain(
      "There is no seed fee: contributors are paid only from read revenue",
    );
    expect(page).toContain("D-052");
  });

  it("marks the numbers the paper names and nothing publishes yet", () => {
    // M21 published the standing formula, the price, the payout minimum and the
    // cycle, so the only placeholders left are M24's paid tiers.
    expect(page).not.toContain("not yet published (M21)");
    expect(page).toContain("not yet published (M24)");
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
      [
        "STANDING_SUBMISSION_VERIFIED",
        `${POLICY.STANDING_SUBMISSION_VERIFIED} standing`,
      ],
      ["STANDING_DISPUTE_UPHELD", `${POLICY.STANDING_DISPUTE_UPHELD} standing`],
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

  it("publishes the price, the payout minimum and the cycle, all from POLICY", () => {
    for (const [name, value] of [
      [
        "READ_PRICE_MICROS_PER_READ",
        `${POLICY.READ_PRICE_MICROS_PER_READ} micro-USD per read`,
      ],
      ["PAYOUT_MINIMUM_MICROS", `${POLICY.PAYOUT_MINIMUM_MICROS} micro-USD`],
      ["PAYOUT_CYCLE", POLICY.PAYOUT_CYCLE],
    ] as const) {
      expect(page, `${name} has no row`).toContain(
        `<td class="mono">${name}</td>`,
      );
      expect(page, `${name} does not print its value`).toContain(
        `<td class="mono">${value}</td>`,
      );
    }
    // The per-thousand figure is derived from the price rather than restated, so
    // a price that moves by decision moves this with it. It is the paper's own
    // worked example at today's number: fifty cents per thousand reads.
    expect(page).toContain("$0.50 per thousand reads");
    expect(page).toContain("$5.00");
  });

  it("groups the dispute and report numbers, and reads each from POLICY", () => {
    expect(page).toContain("Disputes and reports");
    for (const [name, value] of [
      ["FAILURE_REPORT_THRESHOLD", String(POLICY.FAILURE_REPORT_THRESHOLD)],
      ["DISPUTE_STAKE_STANDING", `${POLICY.DISPUTE_STAKE_STANDING} standing`],
      ["DISPUTE_FILING_FEE_CENTS", `${POLICY.DISPUTE_FILING_FEE_CENTS} cents`],
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
    // The stakes are placeholders and the page says so rather than implying
    // that a number nobody priced is a price.
    expect(page).toContain("a stake is a");
    expect(page).toContain("no money");
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
      "/mirror/latest",
      "/how-it-works",
    ];
    for (const path of paths) {
      expect(page, `${path} is not documented`).toContain(path);
    }
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
    // Standing is recomputed over the log rather than read from a column, and
    // the page has to say so: that is the whole difference between a number a
    // reader can check and a score nomankind hands out.
    expect(page).toContain("recomputed over the sealed log");
    expect(page).toContain("formula");
    expect(page).toContain("stored");
    expect(page).toContain(
      "accrued, held, released, clawed_back, paid, carried_forward",
    );
    expect(page).toContain("reconciliations");
    expect(page).toContain("READ_PRICE_MICROS_PER_READ");
    expect(page).toContain("PAYOUT_MINIMUM_MICROS");
    expect(page).toContain("PAYOUT_CYCLE");
    expect(page).toContain("HOLDBACK_DAYS");
    expect(page).toContain("404 not_found.");
  });

  it("gives standing a command beside the other offline checks", () => {
    expect(page).toContain(`npm run standing -- ${ctx.origin} &lt;operator&gt;`);
  });

  it("names the three units and what each one is", () => {
    expect(page).toContain(">Units</h2>");
    expect(page).toContain("a millionth of a dollar: 1,000,000 to the dollar");
    expect(page).toContain("Standing units, which are not money");
    expect(page).toContain(`${POLICY.DISPUTE_FILING_FEE_CENTS} cents`);
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
    expect(page).toContain("M24");
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
      "author_mismatch",
      "POST /entries refusal",
      "entry_not_verified",
      "not_correction",
      "missing_citation",
      "subject_mismatch",
      "self_dispute",
      "dispute_open",
      // Decision D-080: the source gate is asked a second time here, about the
      // entry being challenged, after the filing rules and before the links.
      "unknown_authority",
      "source_not_official",
      "bad_report_link",
      "bad_revalidation_link",
      // Section 9: standing gates the stake, checked after every M20 rule and
      // before anything is written.
      "insufficient_standing",
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

  it("says in words what each mechanism is, and that stakes are placeholders", () => {
    expect(page).toContain("A dispute is a challenge to a verified entry");
    expect(page).toContain("A revalidation request is an operator asking");
    expect(page).toContain("A failure report is a signed report");
    expect(page).toContain("distinct registered\n          operators");
    expect(page).toContain("drawn from the trusted pool by the public randomness");
    expect(page).toContain("ledger records and nothing else");
    expect(page).toContain("No\n          money moves on any of them today.");
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
      "min_source=official|recognized, domain=<slug>",
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

  it("counts the status stages as the status rules count them", () => {
    // The mirror export is a stage of the pipeline now, so the endpoint's own
    // description says thirteen: a page naming twelve would be documenting a
    // shape the route no longer answers.
    expect(page).toContain("thirteen of them");
    expect(page).not.toContain("twelve of them");
  });

  it("carries no script and no inline style", () => {
    expect(page).not.toContain("<script");
    expect(page).not.toContain(' style="');
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
    expect(page).toContain("Name a domain and sign its independence attestation");
    expect(page).toContain("mock-verified-");
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
    expect(page).toContain("<title>nomankind</title>");
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
    expect(page).toContain("Paid for being right.");
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
    expect(page).toContain(
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
    expect(page).toContain("Quotations you can trace.");
    expect(page).toContain(
      "CODE APACHE-2.0 · DATA CC0 · TRAINING ON THE FEED IS FREE",
    );
  });

  it("survives the content-security-policy: no script, no inline style", () => {
    expect(page).not.toContain("<script");
    expect(page).not.toContain("style=");
    expect(page).not.toContain("javascript:");
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

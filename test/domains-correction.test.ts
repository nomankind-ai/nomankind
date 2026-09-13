/**
 * The challenge, in every registered domain (the QA of 2026-09-12, a D-096 gap).
 *
 * A dispute is filed as an entry: the challenge is a `correction` in the domain
 * of the entry it challenges (whitepaper Section 6, "Dispute"). Neither
 * ai-governance nor ai-safety listed that category, so every challenge in either
 * one died at the submission door with `category_not_in_domain` — and with it
 * `overturned_by`, the unlearn signal, and the whole of what makes the record
 * correctable. The two rows carry ai-ecosystem's `correction` now: no staleness
 * window, no transcript, no official source, and — in ai-safety — neither the
 * disclosure nor the version-staleness rule, both of which are about what a
 * system does.
 *
 * Three things are held here: the tables say so, the door agrees, and the two
 * places a reader looks — the published registry document and the domains page —
 * say the same thing the module does.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  DOMAIN_SLUGS,
  domainPolicy,
  isDisclosureCategory,
  isDomainCategory,
  isOfficialRequiredCategory,
  isTranscriptCategory,
  isVersionStalenessCategory,
  sourcePolicy,
} from "../src/policy.js";
import { checkSubmission, entryIdFor } from "../src/submit.js";
import { DOMAIN_COPY, renderDomains } from "../src/ui/pages/domains.js";
import { makeAgent } from "./helpers/registry.js";
import { SUBMIT_NOW, submittedCore } from "./helpers/submit.js";

const GOVERNANCE = "ai-governance";
const SAFETY = "ai-safety";
const DISPUTABLE = [GOVERNANCE, SAFETY] as const;

const AT = SUBMIT_NOW.toISOString();
const SNAPSHOT = `sha256:${"b".repeat(64)}`;

const registryDoc = readFileSync(
  fileURLToPath(
    new URL("../schema/nomankind-domain-registry-v1.md", import.meta.url),
  ),
  "utf8",
);

/** One domain's section of the published document, heading to heading. */
function section(slug: string): string {
  const start = registryDoc.indexOf(`### ${slug}`);
  expect(start, `${slug} has no section`).toBeGreaterThan(-1);
  const next = registryDoc.indexOf("\n### ", start + 1);
  return next === -1 ? registryDoc.slice(start) : registryDoc.slice(start, next);
}

// ---------------------------------------------------------------------------
// The tables
// ---------------------------------------------------------------------------

describe("correction, in every registered domain", () => {
  it("is a category every domain admits", () => {
    for (const slug of DOMAIN_SLUGS) {
      expect(isDomainCategory(slug, "correction"), slug).toBe(true);
    }
  });

  it("is ai-ecosystem's row, unchanged, in the two domains D-096 added", () => {
    for (const slug of DISPUTABLE) {
      const policy = domainPolicy(slug);
      // An event: a correction happened, and having happened stays true.
      expect(policy.staleness_window_days["correction"], slug).toBeNull();
      // Nothing here is measured against a model, so nothing is transcribed.
      expect(isTranscriptCategory(slug, "correction"), slug).toBe(false);
      // The rule that binds a challenge is the one its target carries, which
      // the dispute door checks against the challenged entry's own category.
      expect(isOfficialRequiredCategory(slug, "correction"), slug).toBe(false);
      expect(
        [...sourcePolicy(slug).official_required],
        `${slug}'s official-required`,
      ).not.toContain("correction");
    }
  });

  it("carries neither of ai-safety's two extra rules", () => {
    expect(isDisclosureCategory(SAFETY, "correction")).toBe(false);
    expect(isVersionStalenessCategory(SAFETY, "correction")).toBe(false);
    const safety = domainPolicy(SAFETY);
    expect([...safety.disclosure!.categories]).not.toContain("correction");
    expect([...safety.version_staleness!.categories]).not.toContain(
      "correction",
    );
  });
});

// ---------------------------------------------------------------------------
// The door
// ---------------------------------------------------------------------------

describe("the submission door, on a challenge in the new domains", () => {
  /** A correction as a challenger files it: cited, snapshotted, stated. */
  const proposal = (domain: string, subject: string) => ({
    subject,
    category: "correction",
    domain,
    claim: "The recorded value is wrong.",
    before: "the recorded value",
    after: "the corrected value",
    effective_at: "2026-09-01",
    citation: "https://www.example.com/the-correction",
    snapshot_hash: SNAPSHOT,
  });

  it("accepts a correction in each domain that D-096 registered", async () => {
    const author = await makeAgent();
    for (const [domain, subject] of [
      [GOVERNANCE, "example/ai-act"],
      [SAFETY, "example/kestrel-9"],
    ] as const) {
      const core = await submittedCore(author, proposal(domain, subject));
      expect([
        domain,
        checkSubmission(core, {
          now: AT,
          requestAgent: author.agentId,
          authorOperator: null,
          expectedId: await entryIdFor(core),
        }),
      ]).toEqual([domain, { ok: true }]);
    }
  });

  it("still refuses a category the domain does not admit", async () => {
    const author = await makeAgent();
    // The refusal is alive and well: what changed is which categories these two
    // domains hold, not that a foreign category passes now.
    const core = await submittedCore(
      author,
      { ...proposal(GOVERNANCE, "example/ai-act"), category: "incident" },
    );
    expect(
      checkSubmission(core, {
        now: AT,
        requestAgent: author.agentId,
        authorOperator: null,
        expectedId: await entryIdFor(core),
      }),
    ).toEqual({ ok: false, reason: "category_not_in_domain" });
  });
});

// ---------------------------------------------------------------------------
// What a reader is told
// ---------------------------------------------------------------------------

describe("the two published faces of the registry", () => {
  it("names the category and its window in each domain's own section", () => {
    for (const slug of DISPUTABLE) {
      const own = section(slug);
      expect(own, `${slug}'s categories`).toContain("`correction`");
      // The staleness table of that section, and not another domain's.
      expect(own, `${slug}'s staleness table`).toContain("| correction | null |");
    }
  });

  it("says in each section that a correction needs no official source", () => {
    for (const slug of DISPUTABLE) {
      expect(section(slug).replace(/\s*\n>?\s*/g, " ")).toContain(
        "the rule that binds a challenge is the one its target carries",
      );
    }
  });

  it("lists it on the domains page, in each domain's own panel", () => {
    const counts: Record<
      string,
      { entries: number; trustedOperators: number }
    > = {};
    for (const slug of DOMAIN_SLUGS) {
      counts[slug] = { entries: 1, trustedOperators: 1 };
    }
    const page = renderDomains(
      {
        path: "/domains",
        environment: "demo",
        origin: "https://demo.example",
        version: "v0.1.29",
      } as Parameters<typeof renderDomains>[0],
      { counts },
    );

    for (const slug of DOMAIN_SLUGS) {
      expect(DOMAIN_COPY[slug], `${slug} has no copy`).toBeDefined();
      const start = page.indexOf(`id="${slug}"`);
      expect(start, `${slug} has no panel`).toBeGreaterThan(-1);
      const next = page.indexOf(`<section class="panel"`, start);
      const panel = next === -1 ? page.slice(start) : page.slice(start, next);
      expect(panel, `${slug}'s categories`).toContain(
        `<span class="badge ">correction</span>`,
      );
    }
  });
});

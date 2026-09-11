/**
 * The registry with three domains in it (decision D-096).
 *
 * test/domains.test.ts is about the domain key and the rules keyed by it. This
 * file is about the tables themselves now that there is more than one set of
 * them: that every domain's tables are internally consistent, that the schema's
 * two enums are exactly what the registry says they are, and that the published
 * document says the same thing as `DOMAINS` down to the sentence an operator
 * signs.
 *
 * The rule under all of it: a domain's categories are the domain's. The
 * schema's enum is their union and never a licence to use one of them anywhere,
 * so every per-domain list here is checked against that domain's own categories
 * rather than against the enum.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  DOMAINS,
  DOMAIN_SLUGS,
  domainPolicy,
  sourcePolicy,
} from "../src/policy.js";

const schema = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../schema/nomankind-entry-schema.json", import.meta.url)),
    "utf8",
  ),
) as {
  properties: { domain: { enum: string[] }; category: { enum: string[] } };
  allOf: { if: { properties: { category: { enum?: string[] } } } }[];
};

const registryDoc = readFileSync(
  fileURLToPath(
    new URL("../schema/nomankind-domain-registry-v1.md", import.meta.url),
  ),
  "utf8",
);

/** The document with its line wrapping taken out, so a sentence can be found. */
const registryProse = registryDoc.replace(/\s*\n>?\s*/g, " ");

/** A hostname: lowercase labels, no scheme, no port, no path, no trailing dot. */
const HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

const NEW_DOMAINS = ["ai-governance", "ai-safety"] as const;

/** The sentences D-096 fixes. Typed out here rather than read from the module. */
const ATTESTATION_TEXTS: Readonly<Record<string, string>> = {
  "ai-governance":
    "No model provider, and no body that issues an instrument this record checks, holds control of, or a beneficial stake in, this operator.",
  "ai-safety":
    "No model provider, no guardrail vendor, and no party funded by one, holds control of, or a beneficial stake in, this operator.",
};

// ---------------------------------------------------------------------------
// The two enums
// ---------------------------------------------------------------------------

describe("the schema's enums and the registry", () => {
  it("has the domain enum as its slug list, in that order", () => {
    expect([...DOMAIN_SLUGS]).toEqual(schema.properties.domain.enum);
    expect([...DOMAIN_SLUGS]).toEqual([
      "ai-ecosystem",
      "ai-governance",
      "ai-safety",
    ]);
  });

  it("has the category enum as the union of every domain's categories", () => {
    const union = new Set<string>();
    for (const slug of DOMAIN_SLUGS) {
      for (const category of domainPolicy(slug).categories) union.add(category);
    }

    expect([...union].sort()).toEqual([...schema.properties.category.enum].sort());
    // The union is a union: no category is listed twice in the enum, and no
    // domain lists one of its own twice either.
    expect(schema.properties.category.enum.length).toBe(
      new Set(schema.properties.category.enum).size,
    );
    for (const slug of DOMAIN_SLUGS) {
      const categories = domainPolicy(slug).categories;
      expect(new Set(categories).size).toBe(categories.length);
    }
  });
});

// ---------------------------------------------------------------------------
// Every domain's tables, against that domain's own categories
// ---------------------------------------------------------------------------

describe("every registered domain's tables", () => {
  it("covers exactly its own categories with a staleness window", () => {
    for (const slug of DOMAIN_SLUGS) {
      const domain = domainPolicy(slug);

      expect(
        Object.keys(domain.staleness_window_days).sort(),
        `${slug}'s staleness table`,
      ).toEqual([...domain.categories].sort());
      for (const window of Object.values(domain.staleness_window_days)) {
        if (window === null) continue;
        expect(Number.isInteger(window)).toBe(true);
        expect(window).toBeGreaterThan(0);
      }
    }
  });

  it("names transcript categories it admits", () => {
    for (const slug of DOMAIN_SLUGS) {
      const domain = domainPolicy(slug);

      for (const category of domain.transcript_categories) {
        expect(domain.categories, `${slug}'s transcript categories`).toContain(
          category,
        );
      }
    }
  });

  it("gates only categories it admits", () => {
    for (const slug of DOMAIN_SLUGS) {
      const domain = domainPolicy(slug);

      for (const category of sourcePolicy(slug).official_required) {
        expect(domain.categories, `${slug}'s official-required`).toContain(
          category,
        );
      }
    }
  });

  it("states every host as a lowercase hostname, no scheme, port or path", () => {
    for (const slug of DOMAIN_SLUGS) {
      const sources = sourcePolicy(slug);
      const hosts = [
        ...Object.values(sources.authorities).flatMap((row) => [...row.hosts]),
        ...sources.recognized_hosts,
      ];

      for (const host of hosts) {
        expect(host, `${slug}: ${host}`).toBe(host.toLowerCase());
        expect(host, `${slug}: ${host}`).toMatch(HOSTNAME);
        expect(host).not.toContain("/");
        expect(host).not.toContain(":");
        expect(host).not.toContain("@");
      }
      expect(new Set(sources.recognized_hosts).size).toBe(
        sources.recognized_hosts.length,
      );
      for (const row of Object.values(sources.authorities)) {
        expect(new Set(row.hosts).size).toBe(row.hosts.length);
      }
    }
  });

  it("marks the fixture row, and only it, in every domain", () => {
    for (const slug of DOMAIN_SLUGS) {
      const authorities = sourcePolicy(slug).authorities;
      const fixtures = Object.entries(authorities)
        .filter(([, row]) => row.fixture === true)
        .map(([key]) => key);

      expect(fixtures, `${slug}'s fixture rows`).toEqual(["example"]);
      expect([...authorities["example"]!.hosts]).toEqual([
        "example.com",
        "example",
      ]);
    }
  });

  it("signs one version, and the sentence D-096 fixed, in each new domain", () => {
    for (const slug of NEW_DOMAINS) {
      const attestation = domainPolicy(slug).attestation;

      expect(attestation.version).toBe("nomankind-independence-v1");
      expect(attestation.text).toBe(ATTESTATION_TEXTS[slug]);
    }
    // Three domains, three different sentences: an attestation is a sentence
    // about a relationship, so signing one is never signing another.
    const texts = DOMAIN_SLUGS.map((slug) => domainPolicy(slug).attestation.text);
    expect(new Set(texts).size).toBe(DOMAIN_SLUGS.length);
  });
});

// ---------------------------------------------------------------------------
// The three fields D-096 added
// ---------------------------------------------------------------------------

describe("the fields D-096 added to a domain's tables", () => {
  it("keeps disclosure and version staleness to ai-safety's own categories", () => {
    const safety = domainPolicy("ai-safety");

    expect(safety.disclosure).toBeDefined();
    expect(safety.version_staleness).toBeDefined();
    for (const category of safety.disclosure!.categories) {
      expect(safety.categories).toContain(category);
      // A payload can only be redacted where there is a transcript to redact.
      expect(safety.transcript_categories).toContain(category);
    }
    for (const category of safety.version_staleness!.categories) {
      expect(safety.categories).toContain(category);
    }
    expect(Number.isInteger(safety.disclosure!.window_days)).toBe(true);
    expect(safety.disclosure!.window_days).toBeGreaterThan(0);
  });

  it("leaves both absent where the domain publishes no such rule", () => {
    expect(domainPolicy("ai-ecosystem").disclosure).toBeUndefined();
    expect(domainPolicy("ai-ecosystem").version_staleness).toBeUndefined();
    expect(domainPolicy("ai-governance").disclosure).toBeUndefined();
    expect(domainPolicy("ai-governance").version_staleness).toBeUndefined();
  });

  it("excludes the subject's own authority where the lists do not coincide", () => {
    // ai-ecosystem's authorities are its excluded parties already, so the
    // per-entry rule adds nothing there and is off; the two new domains are
    // about parties whose own pages are the official source, so it is on.
    expect(domainPolicy("ai-ecosystem").excluded_parties.subject_authority).toBe(
      false,
    );
    for (const slug of NEW_DOMAINS) {
      expect(
        domainPolicy(slug).excluded_parties.subject_authority,
        `${slug}'s subject_authority`,
      ).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// The published document
// ---------------------------------------------------------------------------

describe("the published registry document", () => {
  it("names every domain's categories", () => {
    for (const slug of DOMAIN_SLUGS) {
      expect(registryDoc).toContain(`### ${slug}`);
      for (const category of domainPolicy(slug).categories) {
        expect(registryDoc, `${slug}: ${category}`).toContain(`\`${category}\``);
      }
    }
  });

  it("names every authority key of every domain", () => {
    for (const slug of DOMAIN_SLUGS) {
      for (const [authority, row] of Object.entries(
        sourcePolicy(slug).authorities,
      )) {
        expect(registryDoc, `${slug}: ${authority}`).toContain(
          `| ${authority} | `,
        );
        for (const host of row.hosts) {
          expect(registryDoc, `${slug}: ${host}`).toContain(host);
        }
      }
    }
  });

  it("carries both new attestation sentences verbatim", () => {
    for (const slug of NEW_DOMAINS) {
      expect(registryProse).toContain(ATTESTATION_TEXTS[slug]);
      expect(registryProse).toContain(domainPolicy(slug).excluded_parties.rule);
    }
  });

  it("publishes ai-safety's two subsections", () => {
    expect(registryDoc).toContain("#### Delayed disclosure");
    expect(registryDoc).toContain("#### Staleness on a version change");
    // The window and the segment rule, said in the document rather than only in
    // the module: this is what a reader checks an implementation against.
    expect(registryProse).toContain(
      `The payload is public ${DOMAINS["ai-safety"]!.disclosure!.window_days} days after the entry's \`submitted_at\`.`,
    );
    expect(registryProse).toContain("`<party>/<model>/<version>`");
  });

  it("requires a transcript artifact for every domain's transcript categories", () => {
    // The schema cannot express a per-domain enum, so its first conditional
    // carries the union: an entry in any of these categories requires the
    // frozen artifact in `evidence` and is always observed, and every other
    // category requires `evidence` to be null. Which of them a domain admits
    // stays application-enforced, by `category_not_in_domain`.
    const union = new Set<string>();
    for (const slug of DOMAIN_SLUGS) {
      for (const category of domainPolicy(slug).transcript_categories) {
        union.add(category);
      }
    }
    const conditional = schema.allOf[0]?.if.properties.category.enum ?? [];
    expect([...conditional].sort()).toEqual([...union].sort());
  });

  it("states the author rule that decides which domain a fact is in", () => {
    expect(registryProse).toContain("One fact has one home");
  });
});

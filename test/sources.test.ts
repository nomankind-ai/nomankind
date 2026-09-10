/**
 * The source policy (decision D-080): who may be cited for what.
 *
 * Whitepaper Section 4, and Section 12's "stated entries are about the source,
 * not the world". A stated entry verifies when independent operators confirm the
 * source said what the entry says, and nothing in that sentence asks whether the
 * source is one that should be believed about that subject. This file is about
 * the part of that gap the log can close mechanically: which categories are
 * gated, which hosts count, and what a citation that clears neither is called.
 *
 * Pure throughout: no network, no clock, no storage. Every host and every
 * category is read from src/policy.ts, so nothing here restates a table.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  DEFAULT_DOMAIN,
  DOMAIN_SLUGS,
  domainPolicy,
  excludedPartyDomains,
  isOfficialRequiredCategory,
  providerSources,
  recognizedHosts,
  sourcePolicy,
} from "../src/policy.js";
import {
  MIN_SOURCE_VALUES,
  SOURCE_CLASSES,
  SOURCE_CLASS_ORDER,
  SOURCE_REFUSALS,
  checkSource,
  isSourceClass,
  providerOf,
  sourceClassOf,
  sourceClassSatisfies,
} from "../src/sources.js";

const registryDoc = readFileSync(
  fileURLToPath(new URL("../schema/nomankind-domain-registry-v1.md", import.meta.url)),
  "utf8",
);

const OTHER_DOMAIN = "some-other-domain";

// ---------------------------------------------------------------------------
// The published table
// ---------------------------------------------------------------------------

describe("the source tables", () => {
  it("gates exactly the categories with an authoritative source by nature", () => {
    expect([...sourcePolicy(DEFAULT_DOMAIN).official_required]).toEqual([
      "pricing",
      "limit",
      "deprecation",
      "release",
      "outage",
    ]);
    for (const category of ["pricing", "limit", "deprecation", "release", "outage"]) {
      expect(isOfficialRequiredCategory(DEFAULT_DOMAIN, category)).toBe(true);
    }
    // A transcript category rests on a measurement somebody made and receipted,
    // not on a document, so there is no official page for it to be refused for.
    for (const category of ["behavior", "misbehavior"]) {
      expect(isOfficialRequiredCategory(DEFAULT_DOMAIN, category)).toBe(false);
    }
    // Every gated category is one this domain actually admits.
    for (const category of sourcePolicy(DEFAULT_DOMAIN).official_required) {
      expect(domainPolicy(DEFAULT_DOMAIN).categories).toContain(category);
    }
  });

  it("puts every excluded party in exactly one provider row", () => {
    // The two lists are one statement made twice: a party too close to judge the
    // record is exactly the party whose own pages are authoritative about its own
    // products, so an excluded domain with no provider row would be a subject
    // nobody could ever cite officially, and one in two rows would be a subject
    // with two official sources.
    const rows = Object.entries(sourcePolicy(DEFAULT_DOMAIN).providers).filter(
      ([, row]) => row.fixture !== true,
    );

    for (const party of excludedPartyDomains(DEFAULT_DOMAIN)) {
      const owners = rows.filter(([, row]) => row.hosts.includes(party));
      expect(
        owners.map(([slug]) => slug),
        `${party} must belong to exactly one provider row`,
      ).toHaveLength(1);
    }
  });

  it("marks the fixture row, and only it, as a fixture", () => {
    const providers = sourcePolicy(DEFAULT_DOMAIN).providers;
    const fixtures = Object.entries(providers)
      .filter(([, row]) => row.fixture === true)
      .map(([slug]) => slug);

    expect(fixtures).toEqual(["example"]);
    // RFC 2606's reserved names, which nobody can register: the fixture path is
    // honest about being a fixture rather than borrowing a real provider's name.
    expect([...providers["example"]!.hosts]).toEqual(["example.com", "example"]);
  });

  it("states every host lowercase, with no scheme, port or path", () => {
    const sources = sourcePolicy(DEFAULT_DOMAIN);
    const hosts = [
      ...Object.values(sources.providers).flatMap((row) => [...row.hosts]),
      ...sources.recognized_hosts,
    ];

    for (const host of hosts) {
      expect(host).toBe(host.toLowerCase());
      expect(host).not.toContain("/");
      expect(host).not.toContain(":");
    }
    // No host is listed twice inside one row, and no recognized host is repeated.
    expect(new Set(sources.recognized_hosts).size).toBe(
      sources.recognized_hosts.length,
    );
    for (const row of Object.values(sources.providers)) {
      expect(new Set(row.hosts).size).toBe(row.hosts.length);
    }
  });

  it("says the same thing as the published registry document", () => {
    for (const slug of DOMAIN_SLUGS) {
      const sources = sourcePolicy(slug);
      expect(registryDoc).toContain("**Sources.**");
      for (const category of sources.official_required) {
        expect(registryDoc).toContain(`\`${category}\``);
      }
      for (const [provider, row] of Object.entries(sources.providers)) {
        expect(registryDoc).toContain(`| ${provider} | `);
        for (const host of row.hosts) expect(registryDoc).toContain(host);
      }
      for (const host of sources.recognized_hosts) {
        expect(registryDoc).toContain(host);
      }
    }
    // The judgment the policy does not automate, said in as many words.
    expect(registryDoc.replace(/\s*\n>?\s*/g, " ")).toContain(
      "A validator's approval asserts that the cited page supports the claim.",
    );
    // "Adding a domain" now requires the sources section too.
    expect(registryDoc.replace(/\s*\n>?\s*/g, " ")).toContain(
      "and the sources section",
    );
  });

  it("is frozen, row and all", () => {
    const sources = sourcePolicy(DEFAULT_DOMAIN);
    expect(Object.isFrozen(sources)).toBe(true);
    expect(Object.isFrozen(sources.official_required)).toBe(true);
    expect(Object.isFrozen(sources.providers)).toBe(true);
    expect(Object.isFrozen(sources.recognized_hosts)).toBe(true);
    for (const row of Object.values(sources.providers)) {
      expect(Object.isFrozen(row)).toBe(true);
      expect(Object.isFrozen(row.hosts)).toBe(true);
    }
  });

  it("answers nothing for a domain nobody registered", () => {
    expect(() => sourcePolicy(OTHER_DOMAIN)).toThrow(/unregistered domain/);
    expect(isOfficialRequiredCategory(OTHER_DOMAIN, "pricing")).toBe(false);
    expect(providerSources(OTHER_DOMAIN, "openai")).toBeNull();
    expect([...recognizedHosts(OTHER_DOMAIN)]).toEqual([]);
  });

  it("has no row for a provider nobody published", () => {
    expect(providerSources(DEFAULT_DOMAIN, "openai")).not.toBeNull();
    expect(providerSources(DEFAULT_DOMAIN, "kestrel")).toBeNull();
    // Not a prototype walk: `constructor` is not a provider.
    expect(providerSources(DEFAULT_DOMAIN, "constructor")).toBeNull();
    expect(providerSources(DEFAULT_DOMAIN, 42)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The classes themselves
// ---------------------------------------------------------------------------

describe("the source classes", () => {
  it("names three, strongest first, and ranks them", () => {
    expect([...SOURCE_CLASSES]).toEqual(["official", "recognized", "other"]);
    expect(SOURCE_CLASS_ORDER.official).toBeGreaterThan(
      SOURCE_CLASS_ORDER.recognized,
    );
    expect(SOURCE_CLASS_ORDER.recognized).toBeGreaterThan(
      SOURCE_CLASS_ORDER.other,
    );
  });

  it("offers only the two that mean something as a minimum", () => {
    // "At least other" is a demand nothing fails, so it is not one a reader may
    // write: it would look like a filter and be the unfiltered answer.
    expect([...MIN_SOURCE_VALUES]).toEqual(["official", "recognized"]);
    expect(MIN_SOURCE_VALUES).not.toContain("other");
  });

  it("recognizes a class and nothing else", () => {
    for (const value of SOURCE_CLASSES) expect(isSourceClass(value)).toBe(true);
    for (const value of [null, undefined, "", "OFFICIAL", 1, {}]) {
      expect(isSourceClass(value)).toBe(false);
    }
  });
});

describe("providerOf", () => {
  it("takes the first segment of the subject, lowercased", () => {
    expect(providerOf("openai/gpt-5")).toBe("openai");
    expect(providerOf("OpenAI/GPT-5")).toBe("openai");
    expect(providerOf("google/gemini-3/preview")).toBe("google");
  });

  it("answers null for a subject that names no provider", () => {
    for (const subject of ["gpt-5", "", "/gpt-5", null, 42, undefined]) {
      expect(providerOf(subject)).toBeNull();
    }
  });
});

// ---------------------------------------------------------------------------
// The host rule
// ---------------------------------------------------------------------------

describe("sourceClassOf", () => {
  const official = (citation: string) =>
    sourceClassOf(DEFAULT_DOMAIN, "anthropic/claude-4", citation);

  it("calls a provider's own host official, and names the host it matched", () => {
    expect(official("https://anthropic.com/pricing")).toEqual({
      class: "official",
      matched_host: "anthropic.com",
      provider: "anthropic",
    });
  });

  it("takes a subdomain of a listed host, and reports the most specific match", () => {
    // docs.anthropic.com is listed in its own right and is also a subdomain of
    // anthropic.com; the more specific of the two is the one published.
    expect(official("https://docs.anthropic.com/en/api/pricing")).toEqual({
      class: "official",
      matched_host: "docs.anthropic.com",
      provider: "anthropic",
    });
    // A subdomain of a listed host that is not itself listed still matches.
    expect(official("https://www.anthropic.com/news").matched_host).toBe(
      "anthropic.com",
    );
    expect(
      sourceClassOf(
        DEFAULT_DOMAIN,
        "openai/gpt-5",
        "https://platform.openai.com/docs/pricing",
      ),
    ).toEqual({
      class: "official",
      matched_host: "platform.openai.com",
      provider: "openai",
    });
  });

  it("refuses a lookalike that merely ends with the listed name", () => {
    // The dot is the whole rule: a suffix test without it would hand every
    // lookalike domain in the world the official badge of what it ended with.
    for (const citation of [
      "https://anthropic.com.evil.tld/pricing",
      "https://notanthropic.com/pricing",
      "https://anthropic.company/pricing",
      "https://evil.tld/anthropic.com/pricing",
    ]) {
      expect(official(citation).class).toBe("other");
      expect(official(citation).matched_host).toBeNull();
    }
  });

  it("calls http other, whatever host it names", () => {
    // A plaintext fetch is a source anybody on the path can rewrite, so "the
    // official page said so" is not a thing an http citation can establish.
    expect(official("http://anthropic.com/pricing").class).toBe("other");
    expect(
      sourceClassOf(DEFAULT_DOMAIN, "openai/gpt-5", "http://arxiv.org/abs/1").class,
    ).toBe("other");
  });

  it("calls a citation with a port or userinfo other", () => {
    for (const citation of [
      "https://anthropic.com:8443/pricing",
      "https://anthropic.com:443/pricing",
      "https://user@anthropic.com/pricing",
      "https://user:pass@anthropic.com/pricing",
    ]) {
      expect(official(citation).class).toBe("other");
    }
    // The plain https form of the same page is official, so it is the port and
    // the userinfo doing the work and not something else about the URL.
    expect(official("https://anthropic.com/pricing").class).toBe("official");
  });

  it("calls an editorial, standards or journal host recognized", () => {
    expect(
      sourceClassOf(
        DEFAULT_DOMAIN,
        "openai/gpt-5",
        "https://arxiv.org/abs/2601.00001",
      ),
    ).toEqual({
      class: "recognized",
      matched_host: "arxiv.org",
      provider: "openai",
    });
    // A subdomain of a recognized host counts the same way a provider's does.
    expect(
      sourceClassOf(DEFAULT_DOMAIN, "openai/gpt-5", "https://www.reuters.com/x")
        .class,
    ).toBe("recognized");
  });

  it("calls everything else other, and still names the provider", () => {
    expect(
      sourceClassOf(
        DEFAULT_DOMAIN,
        "openai/gpt-5",
        "https://made-up-site.example/pricing",
      ),
    ).toEqual({
      class: "other",
      matched_host: null,
      provider: "openai",
    });
  });

  it("prefers the subject's own provider over the recognized list", () => {
    // A provider's own page about its own product is the strongest source there
    // is for what that product costs, so official wins where both could match.
    expect(
      sourceClassOf(DEFAULT_DOMAIN, "google/gemini-3", "https://blog.google/x")
        .class,
    ).toBe("official");
  });

  it("never throws, for any input at all", () => {
    for (const citation of [null, undefined, 42, "", "not a url", "file:///x"]) {
      expect(sourceClassOf(DEFAULT_DOMAIN, "openai/gpt-5", citation).class).toBe(
        "other",
      );
    }
    expect(sourceClassOf(OTHER_DOMAIN, "openai/gpt-5", "https://openai.com/").class)
      .toBe("other");
    expect(
      sourceClassOf(DEFAULT_DOMAIN, null, "https://arxiv.org/abs/1"),
    ).toEqual({ class: "recognized", matched_host: "arxiv.org", provider: null });
  });

  it("classifies the fixture provider's reserved hosts as official", () => {
    // The demo's own checkpoint, and every `*.example` host the fixtures cite.
    expect(
      sourceClassOf(DEFAULT_DOMAIN, "example/demo-model", "https://example.com/")
        .class,
    ).toBe("official");
    expect(
      sourceClassOf(
        DEFAULT_DOMAIN,
        "example/kestrel-1",
        "https://kestrel.example/pricing",
      ),
    ).toEqual({
      class: "official",
      matched_host: "example",
      provider: "example",
    });
  });
});

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

describe("checkSource", () => {
  it("names both refusals, in check order", () => {
    expect([...SOURCE_REFUSALS]).toEqual([
      "unknown_provider",
      "source_not_official",
    ]);
  });

  it("passes a category the domain does not gate, whatever the citation", () => {
    for (const category of ["behavior", "misbehavior", "correction"]) {
      expect(
        checkSource(
          DEFAULT_DOMAIN,
          category,
          "kestrel/kestrel-1",
          "https://made-up-site.example/x",
        ),
      ).toEqual({ ok: true });
    }
  });

  it("passes an official-required claim citing the subject's own source", () => {
    expect(
      checkSource(
        DEFAULT_DOMAIN,
        "pricing",
        "openai/gpt-5",
        "https://platform.openai.com/docs/pricing",
      ),
    ).toEqual({ ok: true });
  });

  it("refuses source_not_official for a made-up host", () => {
    expect(
      checkSource(
        DEFAULT_DOMAIN,
        "pricing",
        "openai/gpt-5",
        "https://made-up-site.example/pricing",
      ),
    ).toEqual({ ok: false, reason: "source_not_official" });
  });

  it("refuses source_not_official for an http citation of an official host", () => {
    expect(
      checkSource(
        DEFAULT_DOMAIN,
        "pricing",
        "openai/gpt-5",
        "http://platform.openai.com/docs/pricing",
      ),
    ).toEqual({ ok: false, reason: "source_not_official" });
  });

  it("refuses source_not_official for a recognized host: recognized is not official", () => {
    // A newspaper reporting a price change is a real source and the entry may
    // cite it; what it is not is the provider saying what its own product costs.
    expect(
      checkSource(
        DEFAULT_DOMAIN,
        "pricing",
        "openai/gpt-5",
        "https://reuters.com/technology/openai-price",
      ),
    ).toEqual({ ok: false, reason: "source_not_official" });
  });

  it("refuses unknown_provider before it looks at the citation at all", () => {
    // A provider with no published row has no official source, so the log cannot
    // tell an official page from a lookalike and refuses rather than guessing --
    // even when the citation happens to be somebody else's official host.
    for (const citation of [
      "https://kestrel.example/pricing",
      "https://platform.openai.com/docs/pricing",
    ]) {
      expect(
        checkSource(DEFAULT_DOMAIN, "pricing", "kestrel/kestrel-1", citation),
      ).toEqual({ ok: false, reason: "unknown_provider" });
    }
    // A subject with no provider segment at all names no provider either.
    expect(
      checkSource(DEFAULT_DOMAIN, "pricing", "gpt-5", "https://openai.com/"),
    ).toEqual({ ok: false, reason: "unknown_provider" });
  });

  it("gates every official-required category the same way", () => {
    for (const category of sourcePolicy(DEFAULT_DOMAIN).official_required) {
      expect(
        checkSource(
          DEFAULT_DOMAIN,
          category,
          "openai/gpt-5",
          "https://made-up-site.example/x",
        ),
      ).toEqual({ ok: false, reason: "source_not_official" });
      expect(
        checkSource(
          DEFAULT_DOMAIN,
          category,
          "openai/gpt-5",
          "https://status.openai.com/",
        ),
      ).toEqual({ ok: true });
    }
  });
});

describe("sourceClassSatisfies", () => {
  it("is met by anything when no demand was made", () => {
    for (const value of SOURCE_CLASSES) {
      expect(sourceClassSatisfies(value, undefined)).toBe(true);
      expect(sourceClassSatisfies(value, null)).toBe(true);
    }
    expect(sourceClassSatisfies(null, undefined)).toBe(true);
  });

  it("is met only by a class at least as strong", () => {
    expect(sourceClassSatisfies("official", "official")).toBe(true);
    expect(sourceClassSatisfies("official", "recognized")).toBe(true);
    expect(sourceClassSatisfies("recognized", "recognized")).toBe(true);
    expect(sourceClassSatisfies("recognized", "official")).toBe(false);
    expect(sourceClassSatisfies("other", "recognized")).toBe(false);
    expect(sourceClassSatisfies("other", "official")).toBe(false);
  });

  it("fails a demand when the log has no class at all", () => {
    // Answering "probably" to a reader who asked where the claim came from is
    // the one thing this must never do.
    expect(sourceClassSatisfies(null, "official")).toBe(false);
    expect(sourceClassSatisfies(null, "recognized")).toBe(false);
  });
});

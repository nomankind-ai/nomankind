/**
 * The domain key in the frozen core, and everything keyed by it (D-071).
 *
 * Whitepaper Section 3, "The log": the mechanism does not care about the domain.
 * The tables do, so this file is about the tables — that they are per domain,
 * that they say the same thing as the published registry document, and that
 * every eligibility rule reads the entry's domain rather than a global list.
 *
 * Whitepaper Section 10, in its neutral form: no party whose products or conduct
 * the record checks may control, fund, or validate it in that domain. Which is
 * the rule the last half of this file is about: an operator excluded in one
 * domain stays eligible in another, and being attested somewhere is not being
 * attested everywhere.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { appendEvent, type Attestation, type Event } from "../src/events.js";
import * as evidence from "../src/evidence.js";
import { operatorDomainsAt, operatorDomainsOf } from "../src/derive.js";
import { canonicalize } from "../src/hash.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  generateKeypair,
} from "../src/identity.js";
import * as policy from "../src/policy.js";
import {
  attestationFor,
  DEFAULT_DOMAIN,
  DOMAIN_SLUGS,
  DOMAINS,
  domainPolicy,
  excludedPartyDomains,
  isDomainCategory,
  isRegisteredDomain,
  isTranscriptCategory,
  stalenessWindowDays,
} from "../src/policy.js";
import {
  ATTESTATION_TEXT,
  ATTESTATION_VERSION,
  HASH_TAG_ATTESTATION,
  JOIN_REFUSALS,
  attestationDomain,
  checkDomainJoin,
  isExcludedParty,
  isProviderDomain,
  parseDomainJoinBody,
  signAttestation,
  verifyAttestation,
} from "../src/registry.js";
import { signBytes } from "../src/identity.js";

const schemaPath = fileURLToPath(
  new URL("../schema/nomankind-entry-schema.json", import.meta.url),
);
const registryDocPath = fileURLToPath(
  new URL("../schema/nomankind-domain-registry-v1.md", import.meta.url),
);

const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as {
  properties: { domain: { enum: string[] }; category: { enum: string[] } };
  required: string[];
};
const registryDoc = readFileSync(registryDocPath, "utf8");

/** The document with its line wrapping taken out, so a sentence can be found. */
const registryProse = registryDoc.replace(/\s*\n>?\s*/g, " ");

const OPERATOR = "lattice.example";
const OTHER_DOMAIN = "some-other-domain";
const SIGNED_AT = "2026-09-10T12:00:00Z";

async function makeAgent(): Promise<{ id: string; privateKey: CryptoKey }> {
  const pair = await generateKeypair();
  return {
    id: agentIdFromPublicKey(await exportPublicKeyRaw(pair.publicKey)),
    privateKey: pair.privateKey,
  };
}

const agent = await makeAgent();

// ---------------------------------------------------------------------------
// The registry: the tables, and the document that publishes them
// ---------------------------------------------------------------------------

describe("the domain registry", () => {
  it("has exactly the schema's domain enum as its key set", () => {
    expect(Object.keys(DOMAINS).sort()).toEqual(
      [...schema.properties.domain.enum].sort(),
    );
    expect([...DOMAIN_SLUGS]).toEqual(Object.keys(DOMAINS));
    expect(DOMAIN_SLUGS).toContain(DEFAULT_DOMAIN);
  });

  it("puts the domain in the schema's required key set", () => {
    expect(schema.required).toContain("domain");
  });

  it("keeps nothing category-shaped global any more", () => {
    // The three names the tables used to live under. They are per domain now
    // (DOMAINS), and a name left behind would be a second source of truth.
    expect(Object.keys(policy)).not.toContain("STALENESS_WINDOW_DAYS");
    expect(Object.keys(policy)).not.toContain("MODEL_PROVIDER_DOMAINS");
    expect(Object.keys(policy)).not.toContain("TRANSCRIPT_CATEGORIES");
    expect(Object.keys(evidence)).not.toContain("TRANSCRIPT_CATEGORIES");
    expect(Object.keys(policy.POLICY)).not.toContain("STALENESS_WINDOW_DAYS");
    expect(Object.keys(policy.POLICY)).not.toContain("MODEL_PROVIDER_DOMAINS");
    expect(policy.POLICY.DOMAINS).toBe(DOMAINS);
  });

  it("says the same thing as the published registry document", () => {
    for (const slug of DOMAIN_SLUGS) {
      const domain = domainPolicy(slug);
      expect(registryDoc).toContain(`### ${slug}`);
      expect(registryDoc).toContain(domain.name);
      expect(registryDoc).toContain(domain.attestation.version);
      expect(registryProse).toContain(domain.attestation.text);
      expect(registryDoc).toContain(domain.subject_convention);
      for (const party of domain.excluded_parties.domains) {
        expect(registryDoc).toContain(party);
      }
      for (const [category, window] of Object.entries(
        domain.staleness_window_days,
      )) {
        expect(registryDoc).toContain(
          `| ${category} | ${window === null ? "null" : window} |`,
        );
      }
    }
  });

  it("states the neutral form of the Section 10 rule", () => {
    expect(registryProse).toContain(
      "No party whose products or conduct the record checks may control, fund, or validate it in that domain.",
    );
  });

  it("keeps the schema's category enum the union of every domain's", () => {
    const union = new Set<string>();
    for (const slug of DOMAIN_SLUGS) {
      for (const category of domainPolicy(slug).categories) union.add(category);
    }
    expect([...union].sort()).toEqual(
      [...schema.properties.category.enum].sort(),
    );
  });

  it("is frozen, table and all", () => {
    expect(Object.isFrozen(DOMAINS)).toBe(true);
    for (const slug of DOMAIN_SLUGS) {
      const domain = domainPolicy(slug);
      expect(Object.isFrozen(domain)).toBe(true);
      expect(Object.isFrozen(domain.staleness_window_days)).toBe(true);
      expect(Object.isFrozen(domain.excluded_parties.domains)).toBe(true);
    }
  });
});

describe("the per-domain accessors", () => {
  it("answers the staleness window per domain", () => {
    expect(stalenessWindowDays(DEFAULT_DOMAIN, "pricing")).toBe(90);
    expect(stalenessWindowDays(DEFAULT_DOMAIN, "limit")).toBe(90);
    expect(stalenessWindowDays(DEFAULT_DOMAIN, "behavior")).toBe(30);
    expect(stalenessWindowDays(DEFAULT_DOMAIN, "release")).toBeNull();
    // A category this domain does not admit has no window: there is no such
    // fact to go stale.
    expect(stalenessWindowDays(DEFAULT_DOMAIN, "clinical_trial")).toBeNull();
  });

  it("answers the transcript categories per domain", () => {
    expect(isTranscriptCategory(DEFAULT_DOMAIN, "behavior")).toBe(true);
    expect(isTranscriptCategory(DEFAULT_DOMAIN, "pricing")).toBe(false);
  });

  it("answers which categories a domain admits", () => {
    expect(isDomainCategory(DEFAULT_DOMAIN, "pricing")).toBe(true);
    expect(isDomainCategory(DEFAULT_DOMAIN, "clinical_trial")).toBe(false);
  });

  it("throws for a table nobody registered, and answers no for a category", () => {
    expect(isRegisteredDomain(DEFAULT_DOMAIN)).toBe(true);
    expect(isRegisteredDomain(OTHER_DOMAIN)).toBe(false);
    expect(isRegisteredDomain(42)).toBe(false);

    // A table has to name a real domain: handing back a blank one would apply
    // the wrong windows under a name nobody registered.
    expect(() => domainPolicy(OTHER_DOMAIN)).toThrow(/unregistered domain/);
    expect(() => excludedPartyDomains(OTHER_DOMAIN)).toThrow();
    expect(() => attestationFor(OTHER_DOMAIN)).toThrow();

    // A question about one category answers, so a stranger's malformed file
    // gets a verdict rather than a stack trace (src/verify.ts).
    expect(stalenessWindowDays(OTHER_DOMAIN, "pricing")).toBeNull();
    expect(isTranscriptCategory(OTHER_DOMAIN, "behavior")).toBe(false);
    expect(isDomainCategory(OTHER_DOMAIN, "pricing")).toBe(false);
  });

  it("keys the exclusion by the record's domain", () => {
    expect(isExcludedParty(DEFAULT_DOMAIN, "openai.com")).toBe(true);
    expect(isExcludedParty(DEFAULT_DOMAIN, "research.openai.com")).toBe(true);
    expect(isExcludedParty(DEFAULT_DOMAIN, "lattice.example")).toBe(false);
    // A fork, or a domain, runs its own list: what is excluded here is excluded
    // by this list and by nothing else.
    expect(isExcludedParty(DEFAULT_DOMAIN, "openai.com", ["only.example"])).toBe(
      false,
    );
    expect(isProviderDomain("openai.com")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The attestation, per domain
// ---------------------------------------------------------------------------

describe("the attestation per domain", () => {
  it("signs the default domain's sentence and names the domain on the record", async () => {
    const record = await signAttestation(agent.privateKey, {
      operator: OPERATOR,
      agent: agent.id,
      signed_at: SIGNED_AT,
    });

    expect(record.domain).toBe(DEFAULT_DOMAIN);
    expect(record.version).toBe(attestationFor(DEFAULT_DOMAIN).version);
    expect(record.version).toBe(ATTESTATION_VERSION);
    expect(await verifyAttestation(OPERATOR, agent.id, record)).toBe(true);
    expect(
      await verifyAttestation(OPERATOR, agent.id, record, DEFAULT_DOMAIN),
    ).toBe(true);
    expect(await verifyAttestation(OPERATOR, agent.id, record, OTHER_DOMAIN)).toBe(
      false,
    );
  });

  it("reads a record carrying no domain as the ai-ecosystem attestation", async () => {
    // Exactly the bytes a pre-v0.7 record was signed over: no domain key at all.
    const legacy = await signLegacyAttestation(ATTESTATION_TEXT);

    expect(legacy.domain).toBeUndefined();
    expect(attestationDomain(legacy)).toBe(DEFAULT_DOMAIN);
    expect(await verifyAttestation(OPERATOR, agent.id, legacy)).toBe(true);
    expect(
      await verifyAttestation(OPERATOR, agent.id, legacy, DEFAULT_DOMAIN),
    ).toBe(true);
  });

  it("refuses a record whose text is not this domain's", async () => {
    const wrongText = await signLegacyAttestation(
      "No party whose products or conduct the record checks holds control of this operator.",
    );

    expect(await verifyAttestation(OPERATOR, agent.id, wrongText)).toBe(false);
  });

  it("refuses a record for a domain nobody registered", async () => {
    const record = await signAttestation(agent.privateKey, {
      operator: OPERATOR,
      agent: agent.id,
      signed_at: SIGNED_AT,
    });

    expect(
      await verifyAttestation(OPERATOR, agent.id, {
        ...record,
        domain: OTHER_DOMAIN,
      }),
    ).toBe(false);
  });
});

/** An attestation signed the pre-v0.7 way: no domain key in the signed object. */
async function signLegacyAttestation(text: string): Promise<Attestation> {
  const canonical = canonicalize({
    agent: agent.id,
    operator: OPERATOR,
    signed_at: SIGNED_AT,
    text,
    version: ATTESTATION_VERSION,
  });
  const signature = await signBytes(
    agent.privateKey,
    new TextEncoder().encode(`${HASH_TAG_ATTESTATION}\n${canonical}`),
  );
  return {
    version: ATTESTATION_VERSION,
    signed_at: SIGNED_AT,
    signature: base64url(signature),
  };
}

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// Joining a domain
// ---------------------------------------------------------------------------

describe("parseDomainJoinBody", () => {
  it("reads a domain and an attestation", async () => {
    const attestation = await signAttestation(agent.privateKey, {
      operator: OPERATOR,
      agent: agent.id,
      signed_at: SIGNED_AT,
    });

    expect(
      parseDomainJoinBody({ domain: DEFAULT_DOMAIN, attestation }),
    ).toEqual({
      ok: true,
      value: { domain: DEFAULT_DOMAIN, attestation },
    });
  });

  it("parses an absent attestation as none, not as a bad body", () => {
    expect(parseDomainJoinBody({ domain: DEFAULT_DOMAIN })).toEqual({
      ok: true,
      value: { domain: DEFAULT_DOMAIN, attestation: null },
    });
  });

  it("refuses extra keys and wrong types", () => {
    for (const bad of [
      null,
      "body",
      [],
      {},
      { domain: 42 },
      { domain: DEFAULT_DOMAIN, extra: true },
      { domain: DEFAULT_DOMAIN, attestation: "signed" },
    ]) {
      expect(parseDomainJoinBody(bad)).toEqual({
        ok: false,
        reason: "bad_body",
      });
    }
  });
});

describe("checkDomainJoin", () => {
  it("names its refusals in check order", () => {
    expect([...JOIN_REFUSALS]).toEqual([
      "unregistered_operator",
      "unregistered_domain",
      "excluded_party",
      "already_joined",
      "missing_attestation",
      "bad_attestation",
      "attestation_domain_mismatch",
    ]);
  });

  it("refuses each reason, in that order, first fault winning", async () => {
    const attestation = await signAttestation(agent.privateKey, {
      operator: OPERATOR,
      agent: agent.id,
      signed_at: SIGNED_AT,
    });
    const join = (
      overrides: Partial<Parameters<typeof checkDomainJoin>[0]> = {},
    ) => ({
      operator: OPERATOR,
      agent: agent.id,
      domain: DEFAULT_DOMAIN,
      attestation: attestation as unknown,
      registered: true,
      domains: [] as readonly string[],
      ...overrides,
    });

    expect(await checkDomainJoin(join({ registered: false }))).toEqual({
      ok: false,
      reason: "unregistered_operator",
    });
    expect(await checkDomainJoin(join({ domain: OTHER_DOMAIN }))).toEqual({
      ok: false,
      reason: "unregistered_domain",
    });
    expect(await checkDomainJoin(join({ operator: "openai.com" }))).toEqual({
      ok: false,
      reason: "excluded_party",
    });
    expect(
      await checkDomainJoin(join({ domains: [DEFAULT_DOMAIN] })),
    ).toEqual({ ok: false, reason: "already_joined" });
    expect(await checkDomainJoin(join({ attestation: null }))).toEqual({
      ok: false,
      reason: "missing_attestation",
    });
    expect(
      await checkDomainJoin(
        join({ attestation: { ...attestation, signature: base64url(new Uint8Array(64)) } }),
      ),
    ).toEqual({ ok: false, reason: "bad_attestation" });
  });

  it("takes a legacy record as the ai-ecosystem attestation and admits the join", async () => {
    // attestation_domain_mismatch is the last refusal in the order pinned
    // above, and it cannot be reached while exactly one domain is registered: a
    // record naming an unregistered domain never verifies, so `bad_attestation`
    // wins first, and there is no second registered domain for a verifying
    // record to be for. What can be shown today is the case beside it — a
    // record carrying no domain IS the ai-ecosystem attestation, so a join into
    // ai-ecosystem with one is not a mismatch.
    const legacy = await signLegacyAttestation(ATTESTATION_TEXT);

    expect(
      await checkDomainJoin({
        operator: OPERATOR,
        agent: agent.id,
        domain: DEFAULT_DOMAIN,
        attestation: legacy,
        registered: true,
        domains: [],
      }),
    ).toEqual({ ok: true });
  });

  it("admits an operator excluded in one domain into a domain it is not excluded from", async () => {
    // The exclusion is keyed by the domain being joined and by nothing else.
    // openai.com is on ai-ecosystem's list; a domain whose list it is not on
    // would admit it, which is what `isExcludedParty`'s keying says.
    expect(isExcludedParty(DEFAULT_DOMAIN, "openai.com")).toBe(true);
    expect(isExcludedParty(DEFAULT_DOMAIN, "openai.com", [])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Which domains an operator is attested in
// ---------------------------------------------------------------------------

describe("operatorDomainsAt", () => {
  const AT = "2026-09-10T00:00:00Z";

  async function log(): Promise<Event[]> {
    let events: Event[] = [];
    events = await appendEvent(events, {
      at: AT,
      type: "operator_registered",
      entry_id: null,
      payload: { operator: OPERATOR, maintainer: false, domain: DEFAULT_DOMAIN },
    });
    // A registration sealed before v0.7: no domain at all.
    events = await appendEvent(events, {
      at: AT,
      type: "operator_registered",
      entry_id: null,
      payload: { operator: "beacon.example", maintainer: false },
    });
    events = await appendEvent(events, {
      at: AT,
      type: "operator_joined_domain",
      entry_id: null,
      payload: {
        operator: OPERATOR,
        agent: agent.id,
        domain: DEFAULT_DOMAIN,
        attestation: await signAttestation(agent.privateKey, {
          operator: OPERATOR,
          agent: agent.id,
          signed_at: SIGNED_AT,
        }),
      },
    });
    return events;
  }

  it("folds the registration's domain and every join", async () => {
    const events = await log();
    const domains = operatorDomainsAt(events, events.length - 1);

    expect(domains.get(OPERATOR)).toEqual([DEFAULT_DOMAIN]);
    expect(operatorDomainsOf(events, OPERATOR, events.length - 1)).toEqual([
      DEFAULT_DOMAIN,
    ]);
  });

  it("reads a registration sealed before v0.7 as ai-ecosystem", async () => {
    const events = await log();

    expect(operatorDomainsOf(events, "beacon.example", events.length - 1)).toEqual([
      DEFAULT_DOMAIN,
    ]);
  });

  it("never looks past the position it was asked about", async () => {
    const events = await log();

    expect(operatorDomainsOf(events, OPERATOR, 0)).toEqual([DEFAULT_DOMAIN]);
    expect(operatorDomainsOf(events, "beacon.example", 0)).toEqual([]);
  });

  it("says nothing about an operator the log does not name", async () => {
    const events = await log();

    expect(operatorDomainsOf(events, "nobody.example", events.length - 1)).toEqual(
      [],
    );
  });
});

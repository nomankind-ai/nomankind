/**
 * Every policy number in the whitepaper lives here and nowhere else.
 * Each constant names the whitepaper section it comes from.
 * A few numbers are not in the paper at all: the paper names the rule and
 * leaves the amount to published policy. Those are the maintainer's own
 * choices, each said to be so in its comment and each carrying the decision
 * that set it, and they move only by a later decision.
 */

/**
 * Lifecycle of an entry. Once the trusted pool holds ten operators, three
 * approvals verify and one validator is drawn at random; below ten, two
 * approvals verify and no draw is made.
 */
export const TRUSTED_POOL_SWITCH = 10;

/** Lifecycle of an entry. Until the pool holds ten operators, two approvals verify. */
export const APPROVALS_TO_VERIFY_SMALL_POOL = 2;

/** Lifecycle of an entry. Once the pool holds ten operators, three approvals verify. */
export const APPROVALS_TO_VERIFY_LARGE_POOL = 3;

/** Lifecycle of an entry. Two rejections mark the entry rejected, at either pool size. */
export const REJECTIONS_TO_REJECT = 2;

/** Lifecycle of an entry. Verification needs three verified operators outside the submitter's own. */
export const VERIFICATION_MIN_OUTSIDE_OPERATORS = 3;

/**
 * Lifecycle of an entry. An assigned validator has seventy-two hours to
 * respond; a miss costs standing and the next beacon round draws a replacement.
 */
export const ASSIGNMENT_WINDOW_HOURS = 72;

/**
 * The evidence rule (n-of-k). A validator's reproduction runs the frozen prompt
 * n times; the claim holds when the predicate held in at least k of them.
 */
export const REPRODUCTION_RUNS = 10;
export const REPRODUCTION_HOLDS = 8;

/**
 * Every category in the schema's category enum: the union of every registered
 * domain's categories, and never a global list of what a category may be. Which
 * of them a domain actually admits is `DOMAINS[slug].categories` and nothing
 * else (`isDomainCategory`), because JSON Schema cannot express a per-domain
 * enum without splitting the schema.
 */
export type Category =
  // ai-ecosystem
  | "release"
  | "deprecation"
  | "pricing"
  | "limit"
  | "behavior"
  | "outage"
  | "misbehavior"
  | "correction"
  // ai-governance (D-096)
  | "in_force"
  | "amended"
  | "repealed"
  | "guidance_issued"
  | "enforcement_action"
  // ai-safety (D-096)
  | "commitment_published"
  | "commitment_changed"
  | "commitment_withdrawn"
  | "conduct_observed"
  | "refusal_behavior"
  | "filter_behavior"
  | "safety_eval"
  | "incident";

/**
 * A registered domain's published tables: everything about a domain that is not
 * the mechanism.
 *
 * Whitepaper Section 3, "The log": the mechanism does not care about the domain.
 * A fact is a claim, a citation, a snapshot hash and a set of signatures, and
 * none of those is AI-shaped. What is domain-shaped is the tables -- which
 * categories exist, how long each stays fresh, which carry a transcript, who is
 * too close to judge, how a subject is named -- so those live here, per domain,
 * and nothing category-shaped is global any more.
 *
 * The prose form of every field is schema/nomankind-domain-registry-v1.md; this
 * is the same content in the one place code may read it from.
 */
export interface DomainPolicy {
  readonly name: string;
  readonly categories: readonly Category[];
  /**
   * One row per category this domain admits, and no row for any other: the
   * schema's enum is every domain's categories at once, so a table keyed by all
   * of them would be a domain claiming windows for facts it cannot hold.
   */
  readonly staleness_window_days: Readonly<
    Partial<Record<Category, number | null>>
  >;
  readonly transcript_categories: readonly Category[];
  readonly excluded_parties: {
    readonly rule: string;
    readonly domains: readonly string[];
    /**
     * When true, an operator whose own domain is (or is under) an official host
     * of the entry's subject's authority row is refused from validating,
     * reconfirming, or being drawn for that entry (D-096). The excluded-party
     * list above is about the domain; this is about the single entry, which is
     * what a record of instruments and commitments needs: the body that issued
     * the instrument is the party the record is checking.
     *
     * False where the two lists already coincide -- ai-ecosystem's authorities
     * are its excluded parties -- so nothing there changes.
     *
     * A fixture authority row never triggers it.
     */
    readonly subject_authority: boolean;
  };
  readonly attestation: { readonly version: string; readonly text: string };
  readonly subject_convention: string;
  readonly sources: DomainSourcePolicy;
  /**
   * The categories whose transcript payload may be submitted redacted, and how
   * long the archived payload stays private (D-096). Absent where the domain
   * has no such rule, which is every domain whose transcripts are about a
   * product rather than about what somebody said to a model.
   */
  readonly disclosure?: {
    /** Transcript categories whose request payload may be redacted at submit. */
    readonly categories: readonly Category[];
    /** Days after submitted_at before the archived payload is public. */
    readonly window_days: number;
  };
  /**
   * The categories whose subject carries a version as its third segment, and
   * whose entries go stale when another version of the same model verifies
   * (D-096). Absent where no category of the domain is version-shaped.
   */
  readonly version_staleness?: {
    /** Categories whose subject carries a version as its third segment. */
    readonly categories: readonly Category[];
  };
}

/** One authority's published hosts, and whether the row is a fixture. */
export interface AuthoritySources {
  readonly hosts: readonly string[];
  /**
   * True for the reserved row the demo's own checkpoint cites. A fixture
   * authority is never a real subject, and the test that pins the authorities
   * table against the excluded-party list skips it for exactly that reason.
   */
  readonly fixture?: boolean;
}

/**
 * Who may be cited for what, in one domain (decision D-080).
 *
 * Whitepaper Section 4, and Section 12's "stated entries are about the source,
 * not the world": a stated entry verifies when independent operators confirm the
 * source said what the entry says. Nothing in that sentence asks whether the
 * source is one that should be believed about that subject, so a site made
 * yesterday could carry a pricing claim to verified. This table is the answer,
 * and it is deliberately two different kinds of thing:
 *
 * `official_required` is a gate. Those categories have an authoritative source
 * by nature -- what a product costs, what its limits are, what was released,
 * deprecated, or down is the authority's own to state -- so an entry in one of
 * them must cite the subject's official source or it is refused at submit.
 *
 * `authorities` says what "the subject's official source" means. The subject
 * convention is `<provider>/<model or product>`, so the subject's primary
 * party -- its first path segment -- keys this table. Every excluded party of
 * the domain appears here: a party too close to judge the record is exactly the
 * party whose own pages are authoritative about its own products. An authority
 * with no row has no official source published here, so its official-required
 * claims are refused until a decision adds the row -- refused, and never quietly
 * accepted from anywhere.
 *
 * `recognized_hosts` is a label and never a gate: sources with an editorial
 * process, a standards body, a court or regulator, a journal or a preprint
 * server. It says where a claim came from and leaves the judgment where it
 * belongs. A validator's approval is still what asserts that the cited page
 * supports the claim; this table only says which pages may be cited at all.
 *
 * Not a whitepaper list. The maintainer's published policy (D-080); it grows
 * only by a later decision, and never by an edit anywhere but this file.
 */
export interface DomainSourcePolicy {
  readonly official_required: readonly Category[];
  readonly authorities: Readonly<Record<string, AuthoritySources>>;
  readonly recognized_hosts: readonly string[];
}

/**
 * The AI ecosystem, the domain the log launched with. Its tables are the
 * whitepaper's: the windows of Section 5 ("Freshness and decay"), the excluded
 * parties and the attestation sentence of Section 10, published policy rather
 * than the paper's own list, both moving only by a later decision.
 *
 * A const of its own so the domains registered after it can reference these
 * tables -- the model-provider list, the authorities, the recognized hosts --
 * rather than carry a second copy of them (D-096).
 */
const AI_ECOSYSTEM: DomainPolicy = Object.freeze({
  name: "The AI ecosystem",
  categories: Object.freeze([
    "release",
    "deprecation",
    "pricing",
    "limit",
    "behavior",
    "outage",
    "misbehavior",
    "correction",
  ] as const),
  staleness_window_days: Object.freeze({
    release: null,
    deprecation: null,
    pricing: 90,
    limit: 90,
    behavior: 30,
    outage: null,
    misbehavior: null,
    correction: null,
  }),
  transcript_categories: Object.freeze(["behavior", "misbehavior"] as const),
  excluded_parties: Object.freeze({
    rule:
      "No lab or model provider may be a maintainer, funder, or trusted operator.",
    domains: Object.freeze([
      "openai.com",
      "anthropic.com",
      "google.com",
      "deepmind.google",
      "meta.com",
      "microsoft.com",
      "x.ai",
      "mistral.ai",
      "cohere.com",
      "amazon.com",
      "deepseek.com",
      "alibaba.com",
      "alibabacloud.com",
      "moonshot.cn",
      "01.ai",
      "ai21.com",
      "nvidia.com",
      "ibm.com",
      "baidu.com",
      "tencent.com",
      "bytedance.com",
      "zhipuai.cn",
    ]),
    // This domain's authorities are its excluded parties already, so the
    // per-entry rule adds nothing here and is off.
    subject_authority: false,
  }),
  attestation: Object.freeze({
    version: "nomankind-independence-v1",
    text: "No model provider holds control of, or a beneficial stake in, this operator.",
  }),
  subject_convention: "<provider>/<model or product>",
  sources: Object.freeze({
    official_required: Object.freeze([
      "pricing",
      "limit",
      "deprecation",
      "release",
      "outage",
    ] as const),
    authorities: Object.freeze({
      openai: Object.freeze({
        hosts: Object.freeze([
          "openai.com",
          "platform.openai.com",
          "status.openai.com",
          "help.openai.com",
        ]),
      }),
      anthropic: Object.freeze({
        hosts: Object.freeze([
          "anthropic.com",
          "docs.anthropic.com",
          "status.anthropic.com",
          "claude.com",
          "docs.claude.com",
        ]),
      }),
      google: Object.freeze({
        hosts: Object.freeze([
          "google.com",
          "ai.google.dev",
          "cloud.google.com",
          "status.cloud.google.com",
          "deepmind.google",
          "blog.google",
        ]),
      }),
      meta: Object.freeze({
        hosts: Object.freeze(["meta.com", "ai.meta.com", "llama.com"]),
      }),
      microsoft: Object.freeze({
        hosts: Object.freeze([
          "microsoft.com",
          "azure.microsoft.com",
          "learn.microsoft.com",
        ]),
      }),
      xai: Object.freeze({
        hosts: Object.freeze(["x.ai", "docs.x.ai", "status.x.ai"]),
      }),
      mistral: Object.freeze({
        hosts: Object.freeze([
          "mistral.ai",
          "docs.mistral.ai",
          "status.mistral.ai",
        ]),
      }),
      cohere: Object.freeze({
        hosts: Object.freeze([
          "cohere.com",
          "docs.cohere.com",
          "status.cohere.com",
        ]),
      }),
      amazon: Object.freeze({
        hosts: Object.freeze([
          "amazon.com",
          "aws.amazon.com",
          "docs.aws.amazon.com",
          "health.aws.amazon.com",
        ]),
      }),
      deepseek: Object.freeze({
        hosts: Object.freeze([
          "deepseek.com",
          "api-docs.deepseek.com",
          "status.deepseek.com",
        ]),
      }),
      alibaba: Object.freeze({
        hosts: Object.freeze([
          "alibaba.com",
          "alibabacloud.com",
          "help.aliyun.com",
        ]),
      }),
      moonshot: Object.freeze({
        hosts: Object.freeze(["moonshot.cn", "platform.moonshot.cn"]),
      }),
      // 01.ai publishes the Yi models under the org name `01-ai`, which is
      // what a subject names; the registrable domain is the excluded party.
      "01-ai": Object.freeze({ hosts: Object.freeze(["01.ai"]) }),
      ai21: Object.freeze({
        hosts: Object.freeze(["ai21.com", "docs.ai21.com"]),
      }),
      nvidia: Object.freeze({
        hosts: Object.freeze([
          "nvidia.com",
          "docs.nvidia.com",
          "build.nvidia.com",
        ]),
      }),
      ibm: Object.freeze({
        hosts: Object.freeze(["ibm.com", "cloud.ibm.com"]),
      }),
      baidu: Object.freeze({
        hosts: Object.freeze(["baidu.com", "cloud.baidu.com"]),
      }),
      tencent: Object.freeze({
        hosts: Object.freeze(["tencent.com", "cloud.tencent.com"]),
      }),
      bytedance: Object.freeze({
        hosts: Object.freeze(["bytedance.com", "volcengine.com"]),
      }),
      zhipuai: Object.freeze({
        hosts: Object.freeze(["zhipuai.cn", "open.bigmodel.cn"]),
      }),
      /**
       * The reserved names (RFC 2606): `example.com`, which the demo's own
       * checkpoint and the M14 fixtures cite, and the `example` top-level
       * domain itself, which every `*.example` fixture host is a subdomain of.
       *
       * A fixture row and never a real subject, which is what `fixture` says
       * and what the test pinning this table against the excluded-party list
       * skips it for. Both entries are reserved by IANA and can never be
       * registered by anybody, so nothing published here can become a real
       * authority's official host by someone buying a domain.
       */
      example: Object.freeze({
        hosts: Object.freeze(["example.com", "example"]),
        fixture: true,
      }),
    }),
    recognized_hosts: Object.freeze([
      "arxiv.org",
      "doi.org",
      "openreview.net",
      "acm.org",
      "ieee.org",
      "nature.com",
      "science.org",
      "nist.gov",
      "iso.org",
      "ietf.org",
      "w3.org",
      "sec.gov",
      "federalregister.gov",
      "courtlistener.com",
      "gov.uk",
      "europa.eu",
      "eur-lex.europa.eu",
      "reuters.com",
      "apnews.com",
      "bloomberg.com",
      "nytimes.com",
      "wsj.com",
      "ft.com",
      "theverge.com",
      "techcrunch.com",
      "wired.com",
      "arstechnica.com",
    ]),
  }),
});

/**
 * The guardrail vendors excluded from the AI-safety record, by registrable
 * domain and by any subdomain of one (D-096). A product that decides what a
 * model refuses is a product this domain's entries are about, so its vendor is
 * as close to the record as a model provider is.
 *
 * PLACEHOLDER for the maintainer: the maintainer's own list, not a whitepaper
 * list, exactly as the model-provider list above is. It moves only by a later
 * decision.
 */
const GUARDRAIL_VENDOR_DOMAINS: readonly string[] = Object.freeze([
  "lakera.ai",
  "protectai.com",
  "hiddenlayer.com",
  "calypsoai.com",
  "arthur.ai",
  "guardrailsai.com",
  "patronus.ai",
  "promptfoo.dev",
]);

/**
 * The fixture authority row, shared by every domain: the reserved names of RFC
 * 2606, which nobody can register. One object rather than three copies, so a
 * fixture can never quietly differ between domains.
 */
const EXAMPLE_AUTHORITY: AuthoritySources =
  AI_ECOSYSTEM.sources.authorities["example"]!;

/**
 * AI governance (D-096). What states and intergovernmental bodies have put in
 * force about AI: an instrument's force, its amendment, its repeal, the
 * guidance issued under it, and the enforcement taken under it.
 *
 * The excluded parties are two kinds of party at once. The model providers are
 * ai-ecosystem's list unchanged -- a provider is as close to a rule about it as
 * to a price of it -- and the issuing bodies are excluded per entry rather than
 * by list, because the body that issued the instrument is named by the entry's
 * own subject (`subject_authority`).
 */
const AI_GOVERNANCE: DomainPolicy = Object.freeze({
  name: "AI governance",
  categories: Object.freeze([
    "in_force",
    "amended",
    "repealed",
    "guidance_issued",
    "enforcement_action",
  ] as const),
  staleness_window_days: Object.freeze({
    /**
     * PLACEHOLDER for the maintainer: an instrument in force stays in force
     * until something changes it, but what is in force is worth re-reading on a
     * cadence, and a year is that cadence. Not a whitepaper number; it moves
     * only by a later decision, as the M20 and M21 numbers do.
     */
    in_force: 365,
    // An amendment and a repeal happened, and having happened stays true.
    amended: null,
    repealed: null,
    /** PLACEHOLDER for the maintainer, on the same cadence as `in_force`. */
    guidance_issued: 365,
    // An enforcement action happened: an event, and no window.
    enforcement_action: null,
  }),
  // Nothing here is measured against a model: every category rests on a
  // document somebody published.
  transcript_categories: Object.freeze([] as const),
  excluded_parties: Object.freeze({
    rule:
      "No body that issues an instrument this domain records, and no model provider, may be a maintainer, funder, or trusted operator of the AI-governance record.",
    domains: AI_ECOSYSTEM.excluded_parties.domains,
    subject_authority: true,
  }),
  attestation: Object.freeze({
    version: "nomankind-independence-v1",
    text: "No model provider, and no body that issues an instrument this record checks, holds control of, or a beneficial stake in, this operator.",
  }),
  subject_convention: "<jurisdiction or body>/<instrument slug>",
  sources: Object.freeze({
    // What an instrument says, when it took force, when it was amended or
    // repealed, and what guidance was issued under it are the issuing body's
    // own to state. An enforcement action is not: it is recorded by a court or
    // a regulator, which the recognized list covers.
    official_required: Object.freeze([
      "in_force",
      "amended",
      "repealed",
      "guidance_issued",
    ] as const),
    /**
     * PLACEHOLDER for the maintainer: the rows below are the jurisdictions and
     * bodies the record starts with, each host fetched once and confirmed to
     * answer. The table grows by a later decision and never by an edit
     * anywhere but this file.
     */
    authorities: Object.freeze({
      eu: Object.freeze({
        hosts: Object.freeze([
          "europa.eu",
          "eur-lex.europa.eu",
          "digital-strategy.ec.europa.eu",
        ]),
      }),
      coe: Object.freeze({ hosts: Object.freeze(["coe.int"]) }),
      us: Object.freeze({
        hosts: Object.freeze([
          "federalregister.gov",
          "whitehouse.gov",
          "congress.gov",
          "govinfo.gov",
          "regulations.gov",
        ]),
      }),
      "us-ca": Object.freeze({
        hosts: Object.freeze(["ca.gov", "leginfo.legislature.ca.gov"]),
      }),
      "us-co": Object.freeze({
        hosts: Object.freeze(["colorado.gov", "leg.colorado.gov"]),
      }),
      "us-ny": Object.freeze({
        hosts: Object.freeze(["ny.gov", "nysenate.gov"]),
      }),
      uk: Object.freeze({
        hosts: Object.freeze(["gov.uk", "legislation.gov.uk"]),
      }),
      iso: Object.freeze({ hosts: Object.freeze(["iso.org"]) }),
      nist: Object.freeze({ hosts: Object.freeze(["nist.gov"]) }),
      oecd: Object.freeze({ hosts: Object.freeze(["oecd.org", "oecd.ai"]) }),
      unesco: Object.freeze({ hosts: Object.freeze(["unesco.org"]) }),
      un: Object.freeze({ hosts: Object.freeze(["un.org"]) }),
      example: EXAMPLE_AUTHORITY,
    }),
    // The ai-ecosystem list, and the courts and data-protection bodies that
    // record what was enforced under an instrument.
    recognized_hosts: Object.freeze([
      ...AI_ECOSYSTEM.sources.recognized_hosts,
      "curia.europa.eu",
      "supremecourt.gov",
      "edpb.europa.eu",
    ]),
  }),
});

/**
 * AI safety (D-096). What non-state parties committed to about harm to people,
 * and what their systems and their guardrail products actually do: a published
 * commitment, a change or a withdrawal of one, conduct observed against it, a
 * refusal, a filter, a safety evaluation, and an incident.
 *
 * Three categories are observed and carry a frozen transcript, which is what
 * the delayed-disclosure rule is for: the payload that produced a refusal is
 * often the sensitive half of the evidence, so it may be archived redacted and
 * opened on a published window (`disclosure`). Four are about one version of
 * one model, which is what `version_staleness` is for: an observation of a
 * model is about the version it was made against, and a later version's
 * verified observation retires it.
 */
const AI_SAFETY: DomainPolicy = Object.freeze({
  name: "AI safety",
  categories: Object.freeze([
    "commitment_published",
    "commitment_changed",
    "commitment_withdrawn",
    "conduct_observed",
    "refusal_behavior",
    "filter_behavior",
    "safety_eval",
    "incident",
  ] as const),
  staleness_window_days: Object.freeze({
    // A commitment published, changed or withdrawn happened, and having
    // happened stays true.
    commitment_published: null,
    commitment_changed: null,
    commitment_withdrawn: null,
    /**
     * PLACEHOLDER for the maintainer: what a system does is as volatile as
     * ai-ecosystem's `behavior`, so the three observed categories carry that
     * domain's thirty days. Not a whitepaper number; it moves only by a later
     * decision, as the M20 and M21 numbers do.
     */
    conduct_observed: 30,
    /** PLACEHOLDER for the maintainer, as `conduct_observed` is. */
    refusal_behavior: 30,
    /** PLACEHOLDER for the maintainer, as `conduct_observed` is. */
    filter_behavior: 30,
    /**
     * PLACEHOLDER for the maintainer: an evaluation is a heavier measurement
     * than a single observation and moves more slowly, so it carries a quarter
     * rather than a month.
     */
    safety_eval: 90,
    // An incident happened.
    incident: null,
  }),
  // Always observed, always a frozen transcript in `evidence`, exactly as
  // behavior and misbehavior are. `safety_eval` carries its measurement in
  // `observation`; `incident` and the three commitment categories are stated.
  transcript_categories: Object.freeze([
    "conduct_observed",
    "refusal_behavior",
    "filter_behavior",
  ] as const),
  excluded_parties: Object.freeze({
    rule:
      "No model provider, no guardrail vendor, and no party funded by one may be a maintainer, funder, or trusted operator of the AI-safety record.",
    domains: Object.freeze([
      ...AI_ECOSYSTEM.excluded_parties.domains,
      ...GUARDRAIL_VENDOR_DOMAINS,
    ]),
    subject_authority: true,
  }),
  attestation: Object.freeze({
    version: "nomankind-independence-v1",
    text: "No model provider, no guardrail vendor, and no party funded by one, holds control of, or a beneficial stake in, this operator.",
  }),
  // The second form is the version-staleness categories': an observation is
  // about the version it was made against, so the version is part of the name.
  subject_convention: "<party>/<document or model>, or <party>/<model>/<version>",
  sources: Object.freeze({
    // What a party committed to, changed, or withdrew is that party's own to
    // state. Conduct, a refusal, a filter, an evaluation and an incident are
    // not: they are what somebody else found.
    official_required: Object.freeze([
      "commitment_published",
      "commitment_changed",
      "commitment_withdrawn",
    ] as const),
    /**
     * Every ai-ecosystem authority row, unchanged -- a provider's own pages are
     * authoritative about the provider's own commitments -- plus the guardrail
     * vendors, each on its own host, and the civil-society and industry bodies
     * that publish commitments of their own.
     *
     * PLACEHOLDER for the maintainer: the rows added here were each fetched
     * once and confirmed to answer, and the table grows by a later decision.
     */
    authorities: Object.freeze({
      ...AI_ECOSYSTEM.sources.authorities,
      lakera: Object.freeze({ hosts: Object.freeze(["lakera.ai"]) }),
      protectai: Object.freeze({ hosts: Object.freeze(["protectai.com"]) }),
      hiddenlayer: Object.freeze({ hosts: Object.freeze(["hiddenlayer.com"]) }),
      calypsoai: Object.freeze({ hosts: Object.freeze(["calypsoai.com"]) }),
      arthur: Object.freeze({ hosts: Object.freeze(["arthur.ai"]) }),
      guardrailsai: Object.freeze({
        hosts: Object.freeze(["guardrailsai.com"]),
      }),
      patronus: Object.freeze({ hosts: Object.freeze(["patronus.ai"]) }),
      promptfoo: Object.freeze({ hosts: Object.freeze(["promptfoo.dev"]) }),
      pai: Object.freeze({ hosts: Object.freeze(["partnershiponai.org"]) }),
      fli: Object.freeze({ hosts: Object.freeze(["futureoflife.org"]) }),
      fmf: Object.freeze({ hosts: Object.freeze(["frontiermodelforum.org"]) }),
      mlcommons: Object.freeze({ hosts: Object.freeze(["mlcommons.org"]) }),
    }),
    // The ai-ecosystem list, and the public register of AI incidents.
    recognized_hosts: Object.freeze([
      ...AI_ECOSYSTEM.sources.recognized_hosts,
      "incidentdatabase.ai",
    ]),
  }),
  disclosure: Object.freeze({
    categories: Object.freeze([
      "conduct_observed",
      "refusal_behavior",
      "filter_behavior",
    ] as const),
    /**
     * PLACEHOLDER for the maintainer: long enough that publishing the payload
     * is not itself the harm, short enough that the evidence becomes public
     * while the fact is still fresh. Not a whitepaper number; it moves only by
     * a later decision, as the M20 and M21 numbers do.
     */
    window_days: 90,
  }),
  version_staleness: Object.freeze({
    categories: Object.freeze([
      "conduct_observed",
      "refusal_behavior",
      "filter_behavior",
      "safety_eval",
    ] as const),
  }),
});

/**
 * Every registered domain, keyed by slug. The key set is exactly the schema's
 * `domain` enum, and test/domains.test.ts pins that the two never drift.
 *
 * Three domains are registered (D-096): ai-ecosystem, ai-governance and
 * ai-safety. One fact has one home -- what an instrument puts in force belongs
 * to governance, what a non-state party committed to about harm and what its
 * systems do belongs to safety, what models cost and do stays in the
 * ecosystem -- and the domain is in the signed core, so nothing can be moved
 * between them afterwards.
 *
 * ai-ecosystem's windows are the whitepaper's ("Freshness and decay": volatile categories
 * carry a staleness window from the last-confirmed date -- ninety days for
 * pricing and rate limits, thirty for behavior; event categories carry none,
 * because once they happened they stay true). The excluded-party list and the
 * attestation sentence are Section 10's, published policy and not the paper's
 * own list: both move only by a later decision.
 */
export const DOMAINS: Readonly<Record<string, DomainPolicy>> = Object.freeze({
  "ai-ecosystem": AI_ECOSYSTEM,
  "ai-governance": AI_GOVERNANCE,
  "ai-safety": AI_SAFETY,
});

/** Every registered slug, in the order DOMAINS declares them. */
export const DOMAIN_SLUGS: readonly string[] = Object.freeze(
  Object.keys(DOMAINS),
);

/**
 * The domain a record that names none belongs to.
 *
 * Not a default in the sense of a fallback anybody may lean on: it is what a
 * legacy v0.6 core, and a registration sealed before v0.7, actually meant --
 * ai-ecosystem was the only domain there was. New records name their domain.
 */
export const DEFAULT_DOMAIN = "ai-ecosystem";

/** Whether a slug names a registered domain. */
export function isRegisteredDomain(slug: unknown): slug is string {
  return (
    typeof slug === "string" &&
    Object.prototype.hasOwnProperty.call(DOMAINS, slug)
  );
}

/**
 * One domain's tables. Throws on an unregistered slug rather than returning a
 * blank: a caller that has not checked `isRegisteredDomain` first is asking a
 * question about a domain that does not exist, and answering it with defaults
 * would apply the wrong windows under a name nobody registered.
 */
export function domainPolicy(domain: string): DomainPolicy {
  const policy = isRegisteredDomain(domain) ? DOMAINS[domain] : undefined;
  if (policy === undefined) {
    throw new Error(`domainPolicy: unregistered domain: ${String(domain)}`);
  }
  return policy;
}

/**
 * The staleness window for one category of one domain, in days, or null when
 * the category carries none. A category the domain does not admit carries no
 * window either: there is no such fact to go stale, and neither does anything
 * in a domain nobody registered.
 *
 * The three accessors below answer rather than throw, unlike `domainPolicy`:
 * each is a question about one category, and the honest answer for a domain or
 * a category that does not exist is no window, no transcript, no such category
 * -- which is what keeps a stranger's malformed file answerable with a verdict
 * instead of a stack trace (src/verify.ts).
 */
export function stalenessWindowDays(
  domain: string,
  category: unknown,
): number | null {
  if (!isRegisteredDomain(domain) || typeof category !== "string") return null;
  const table = domainPolicy(domain).staleness_window_days as Readonly<
    Record<string, number | null>
  >;
  return table[category] ?? null;
}

/** Whether this category of this domain carries its evidence as a transcript. */
export function isTranscriptCategory(
  domain: string,
  category: unknown,
): boolean {
  if (!isRegisteredDomain(domain) || typeof category !== "string") return false;
  return (domainPolicy(domain).transcript_categories as readonly string[]).includes(
    category,
  );
}

/** Whether this category is one the domain admits at all. */
export function isDomainCategory(domain: string, category: unknown): boolean {
  if (!isRegisteredDomain(domain) || typeof category !== "string") return false;
  return (domainPolicy(domain).categories as readonly string[]).includes(category);
}

/**
 * The registrable domains of the parties excluded from this record's domain --
 * the AI ecosystem's model providers, and whatever a later domain publishes.
 *
 * The neutral rule (Section 10, read without the labs): no party whose products
 * or conduct the record checks may control, fund, or validate it in that domain.
 * The list is the cheap first check and never the whole enforcement; the signed
 * attestation is what binds.
 */
export function excludedPartyDomains(domain: string): readonly string[] {
  return domainPolicy(domain).excluded_parties.domains;
}

/**
 * One domain's source policy: the official-required categories, the authorities
 * table, and the recognized hosts (decision D-080).
 *
 * Throws for a domain nobody registered, exactly as `domainPolicy` does and for
 * the same reason: there is no honest empty answer to "who may be cited in a
 * domain that does not exist", and handing back a blank table would let an
 * official-required claim through under a name nobody published.
 */
export function sourcePolicy(domain: string): DomainSourcePolicy {
  return domainPolicy(domain).sources;
}

/**
 * Whether this category of this domain must cite the subject's official source.
 *
 * Answers rather than throws, like the three accessors above: a category a
 * domain does not admit, or a domain nobody registered, requires nothing here —
 * the submission is refused earlier, by `isRegisteredDomain` and
 * `isDomainCategory`, and this question is not the one that should be raising.
 */
export function isOfficialRequiredCategory(
  domain: string,
  category: unknown,
): boolean {
  if (!isRegisteredDomain(domain) || typeof category !== "string") return false;
  return (
    sourcePolicy(domain).official_required as readonly string[]
  ).includes(category);
}

/**
 * One authority's published hosts in one domain, or null when the table has no
 * row for it.
 *
 * Null is the load-bearing answer: an authority with no row has no official
 * source published here, which is what refuses its official-required claims
 * rather than accepting them from anywhere.
 */
export function authoritySources(
  domain: string,
  authority: unknown,
): AuthoritySources | null {
  if (!isRegisteredDomain(domain) || typeof authority !== "string") return null;
  const table = sourcePolicy(domain).authorities;
  if (!Object.prototype.hasOwnProperty.call(table, authority)) return null;
  return table[authority] ?? null;
}

/** The hosts a domain labels recognized: an editorial, standards, court or journal source. */
export function recognizedHosts(domain: string): readonly string[] {
  if (!isRegisteredDomain(domain)) return EMPTY_HOSTS;
  return sourcePolicy(domain).recognized_hosts;
}

/** The empty answer for a domain nobody registered: nothing is recognized there. */
const EMPTY_HOSTS: readonly string[] = Object.freeze([]);

/** The independence attestation of one domain: the version, and the sentence. */
export function attestationFor(
  domain: string,
): { readonly version: string; readonly text: string } {
  return domainPolicy(domain).attestation;
}

/**
 * The first segment of a subject, lowercased: the party the subject names.
 *
 * The same reading src/sources.ts makes of the same string, written out here
 * rather than imported, because that module reads this one and a cycle between
 * the two would be a table depending on a lookup over itself.
 */
function firstSegment(subject: unknown): string | null {
  if (typeof subject !== "string") return null;
  const slash = subject.indexOf("/");
  if (slash <= 0) return null;
  return subject.slice(0, slash).toLowerCase();
}

/**
 * The official hosts of the authority this entry's subject names (D-096), or
 * nothing at all.
 *
 * Nothing, four ways, and every one of them means "this entry excludes nobody
 * by its subject": a domain nobody registered, a domain whose
 * `excluded_parties.subject_authority` is false (ai-ecosystem, whose
 * authorities are its excluded parties already), a subject whose first segment
 * has no row in the authorities table, and a row marked `fixture` -- the
 * reserved `example` names of RFC 2606, which are a test's authority and never
 * a party with an interest in a record.
 *
 * A lookup and nothing more: who may validate is src/validate.ts's answer, and
 * who may be drawn is src/assign.ts's. This only says which hosts the entry's
 * own subject makes too close to judge it.
 */
export function authorityHostsFor(
  domain: string,
  subject: unknown,
): readonly string[] {
  if (!isRegisteredDomain(domain)) return EMPTY_HOSTS;
  if (!domainPolicy(domain).excluded_parties.subject_authority) {
    return EMPTY_HOSTS;
  }
  const row = authoritySources(domain, firstSegment(subject));
  if (row === null || row.fixture === true) return EMPTY_HOSTS;
  return row.hosts;
}

/**
 * Whether this category of this domain may submit a redacted transcript payload
 * (D-096). False for every domain that publishes no `disclosure` rule.
 */
export function isDisclosureCategory(
  domain: string,
  category: unknown,
): boolean {
  if (!isRegisteredDomain(domain) || typeof category !== "string") return false;
  const disclosure = domainPolicy(domain).disclosure;
  if (disclosure === undefined) return false;
  return (disclosure.categories as readonly string[]).includes(category);
}

/**
 * The days after an entry's `submitted_at` that its archived payload stays
 * private, or null where the domain publishes no disclosure rule.
 */
export function disclosureWindowDays(domain: string): number | null {
  if (!isRegisteredDomain(domain)) return null;
  return domainPolicy(domain).disclosure?.window_days ?? null;
}

/**
 * A subject read as `<party>/<model>/<version>`, or null when it is not that
 * shape.
 *
 * `prefix` is the first two segments together -- the model the observation is
 * about, whatever version it was made against -- and `version` is the third.
 * Null when any of the three is missing or empty, which is what the submit
 * door refuses as `bad_subject_version` for a version-staleness category and
 * what makes every other subject in the log no version's sibling at all.
 *
 * A fourth segment and beyond belong to the version: `openai/gpt-5/2026-08/eu`
 * is a version of `openai/gpt-5` and not a model of its own.
 */
export function versionedSubjectOf(
  subject: unknown,
): { readonly prefix: string; readonly version: string } | null {
  if (typeof subject !== "string") return null;
  const parts = subject.split("/");
  if (parts.length < 3) return null;
  const party = parts[0] ?? "";
  const model = parts[1] ?? "";
  const version = parts.slice(2).join("/");
  if (party === "" || model === "" || version === "") return null;
  if (parts.slice(2).some((segment) => segment === "")) return null;
  return { prefix: `${party}/${model}`, version };
}

/**
 * Whether this category of this domain names a version in its subject's third
 * segment, and so goes stale when another version of the same model verifies
 * (D-096). False for every domain that publishes no `version_staleness` rule.
 */
export function isVersionStalenessCategory(
  domain: string,
  category: unknown,
): boolean {
  if (!isRegisteredDomain(domain) || typeof category !== "string") return false;
  const staleness = domainPolicy(domain).version_staleness;
  if (staleness === undefined) return false;
  return (staleness.categories as readonly string[]).includes(category);
}

/**
 * Incentives / Money. Accrued fees are held for thirty days before payout so an
 * upheld dispute can claw them back before they leave.
 */
export const HOLDBACK_DAYS = 30;

/**
 * The two evidence tiers, named here rather than imported (decision D-087).
 *
 * src/evidence.ts owns `EvidenceTier` and it is the same pair of strings, but
 * evidence imports this module for REPRODUCTION_RUNS and the domain tables, and
 * policy must not import back: a policy number that depended on a rule would be
 * a rule. The two are checked against each other in test/policy.test.ts.
 */
type SplitTier = "stated" | "observed";

/**
 * Incentives / Money, per evidence tier (decision D-087).
 *
 * Of paid-read revenue, fifteen percent goes to the submitter of a stated entry
 * and five to each of its three validators — the paper's launch split. An
 * observed entry pays more, twenty and seven: Section 4, "A submitter who can
 * measure a fact may submit it as observed, and is paid more for it", and
 * Section 9, "observed entries take a larger read share than stated ones, by
 * published policy, so the operators who measure are paid more than the
 * operators who copy".
 *
 * The difference comes out of nomankind's own share and never out of the
 * reader's price, which stays one number per read
 * (READ_PRICE_MICROS_PER_READ). Not whitepaper numbers: the paper names the
 * rule and states no amount, so both splits are the maintainer's published
 * placeholders, moving only by a later decision.
 */
export const READ_SHARE_SPLIT: Readonly<
  Record<SplitTier, Readonly<{ submitter: number; validator: number }>>
> = Object.freeze({
  stated: Object.freeze({ submitter: 15, validator: 5 }),
  observed: Object.freeze({ submitter: 20, validator: 7 }),
});

/**
 * The log / Incentives. An entry's read share is always split among exactly one
 * submitter and three current read-share slot holders.
 */
export const SLOT_COUNT = 3;

/**
 * Incentives / Money. What reaches the contributor pool, per tier: the
 * submitter's share plus SLOT_COUNT validators' — 30 on a stated entry
 * (15 + 3 x 5) and 41 on an observed one (20 + 3 x 7). Both at or above the
 * published floor, which is what "a floor that only rises" means.
 */
export const CONTRIBUTOR_SHARE_PERCENT: Readonly<Record<SplitTier, number>> =
  Object.freeze({ stated: 30, observed: 41 });

/**
 * Lifecycle of an entry (Seal). Witnesses countersign the registry head at an
 * initial interval of five minutes set by policy.
 */
export const SEAL_INTERVAL_MINUTES = 5;

/**
 * The sweep's own cadence: how often src/worker/sweep.ts runs, in minutes. The
 * same five minutes the cron trigger in wrangler.jsonc names, held here because
 * the Sweeper Durable Object (src/worker/sweeper.ts) sets its alarm from it and
 * a timer whose interval was written down twice is a timer that drifts.
 *
 * Not a whitepaper number, and not a rule of any kind: it is operational. It
 * says how often the Worker looks, never how long an assigned validator has
 * (ASSIGNMENT_WINDOW_HOURS) or when a draw is legitimate (src/assign.ts).
 * Moving it changes only how promptly the log catches up.
 */
export const SWEEP_INTERVAL_MINUTES = 5;

/**
 * The status page (decision D-076): how many of its own intervals a periodic
 * stage may fall behind before the page calls it `attention`.
 *
 * Not a whitepaper number and not a rule: Section 11 promises a public status
 * page and says nothing about when a late timer is late enough to mention. Two
 * is the maintainer's own choice — one interval is an ordinary run that has not
 * happened yet, and two is a run that was missed — and it moves by decision.
 *
 * An interval is the stage's own, never a single global one: the sweep timer
 * reads it against SWEEP_INTERVAL_MINUTES and sealing against
 * SEAL_INTERVAL_MINUTES, so a cadence that changes moves its own stage's bar
 * with it.
 */
export const STATUS_ATTENTION_AFTER_INTERVALS = 2;

/**
 * The status page (decision D-076): how long a broken rule may stand before the
 * page calls it `failing` rather than `attention`.
 *
 * The maintainer's own number for the same reason as the one above, and thirty
 * minutes because it is six sweeps: a stage still broken after six chances to
 * fix itself is not waiting on the next run, it is stuck. Minutes rather than
 * intervals because it is one bar for every stage — a reader looking at the page
 * should not have to know each stage's cadence to know what red means.
 */
export const STATUS_FAILING_AFTER_MINUTES = 30;

/**
 * The log (failure reports). Reports from this many distinct verified
 * operators auto-open a revalidation. The paper says the threshold is
 * published policy but states no number, so three is the maintainer's own
 * choice: low enough that a real regression reopens quickly, and it rises by
 * decision if floods appear.
 *
 * Not a whitepaper number. The maintainer's published policy (decision D-032,
 * 2026-09-07), recorded in the Notion Decisions database; it moves only by a
 * later decision.
 */
export const FAILURE_REPORT_THRESHOLD = 3;

/**
 * Lifecycle of an entry, "Dispute": "Filing takes a stake, so burner keys cannot
 * dispute for free. A verified operator stakes standing, a bare key stakes a
 * refundable filing fee, and the amounts are published policy."
 *
 * The paper names the rule and states no amount, so both amounts below are the
 * maintainer's own placeholders (decision D-064): stakes are ledger rows and
 * nothing else until M21 builds the money side, so no money moves on either of
 * them. The maintainer sets the real amounts, and they move only by a later
 * decision.
 *
 * `DISPUTE_STAKE_STANDING` is an operator's stake in standing units;
 * `DISPUTE_FILING_FEE_CENTS` is a bare key's refundable fee in cents.
 */
export const DISPUTE_STAKE_STANDING = 10;
export const DISPUTE_FILING_FEE_CENTS = 1000;

/**
 * Lifecycle of an entry, "Revalidate": "Any operator can also request
 * revalidation of an entry inside its window by staking a small amount of
 * standing ... and requests are capped per operator per window."
 *
 * Neither the amount nor the cap is in the paper, so both are the maintainer's
 * own placeholders (decision D-064), in standing units and in requests
 * respectively. A stake is a ledger row and nothing else until M21; no money
 * moves before then. The cap counts per operator, per entry, per freshness
 * window: one operator may ask for one check of one entry per window, which is
 * what keeps a request from becoming a way to keep an entry permanently under
 * review. Both move only by a later decision.
 */
export const REVALIDATION_REQUEST_STAKE_STANDING = 1;
export const REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW = 1;

/**
 * Lifecycle of an entry (Seal), and "Limitations" ("The identity layer is
 * young"). How many distinct pinned operators must have countersigned the
 * registry head, verifiably, before a seal counts as witnessed.
 *
 * Not a whitepaper number. The paper fixes the *bar* — published keys, no two
 * witnesses under common control, nomankind ineligible — and states no count,
 * so the count is the maintainer's own initial policy: one, because the
 * founding registry's directory is small and a bar nothing can clear is a bar
 * that gets quietly ignored. It rises by a later decision as the witness set
 * grows, and never by an edit anywhere but this file.
 */
export const WITNESSES_REQUIRED = 1;

/**
 * Lifecycle of an entry (Seal). The most events one seal may cover. A run
 * longer than this is not dropped: the seal takes the first thousand and the
 * next run continues from where it stopped, so the chain stays contiguous.
 *
 * Not a whitepaper number, and not a rule: it is operational, a ceiling on the
 * work one sweep does and on the size of one Merkle batch. The maintainer's own
 * choice; it moves only by a later decision.
 */
export const SEAL_MAX_EVENTS = 1000;

/**
 * Lifecycle of an entry (Seal). How many bytes of a witness's published
 * countersignature file are read, from the end: 256 kibibytes.
 *
 * The files are append-only JSONL, already hundreds of kilobytes and growing,
 * and only the newest usable line is ever wanted — so the reader asks for a
 * tail rather than the whole file. Not a whitepaper number; operational, and it
 * moves only by a later decision.
 */
export const WITNESS_FILE_TAIL_BYTES = 262144;

/**
 * Lifecycle of an entry (Seal): "the seal hash is sealed as a memory
 * fingerprint into nomankind's own citizen log at the founding 1F916 registry".
 *
 * Which registry that is, its Ed25519 public key (unpadded base64url, the D-014
 * encoding), which of its logs carries identity events, and the label every
 * nomankind seal is filed under. Pinned here rather than in the adapter for the
 * same reason BEACON is: an offline reader has to be able to recheck a
 * countersignature years later against the same key the collector used.
 *
 * Not a whitepaper number. The maintainer's published choice; it moves only by
 * a later decision.
 */
export const REGISTRY: Readonly<{
  origin: string;
  public_key: string;
  log: string;
  seal_label: string;
}> = Object.freeze({
  origin: "https://1f916.ai",
  public_key: "mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw",
  log: "identity_events",
  seal_label: "nomankind-seal",
});

/**
 * "Limitations" ("The identity layer is young"): the witnesses whose
 * countersignatures nomankind will count, pinned by operator and by key.
 *
 * The registry's own directory is a pointer and never an endorsement, so the
 * set is pinned here and the collector only ever re-checks the directory to see
 * whether a pinned row still says what it said. A row that moved is dropped for
 * that run: code never follows a moved key, and the orchestrator re-pins by
 * decision. Three operators, none of them nomankind's, so no two accepted
 * countersignatures can be under common control.
 *
 * Not a whitepaper list. Decision D-054, re-checked before M25; it moves only
 * by a later decision.
 */
export const WITNESS_PIN: readonly Readonly<{
  id: number;
  operator: string;
  public_key: string;
  url: string;
}>[] = Object.freeze([
  Object.freeze({
    id: 6,
    operator: "commonwealth",
    public_key: "nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M",
    url: "https://raw.githubusercontent.com/GavinOB/1f916-witness/main/witness-state/countersignatures.jsonl",
  }),
  Object.freeze({
    id: 7,
    operator: "head-of-experiments",
    public_key: "BwLjer1DCxSErLiPIOG3fu0vlgmQierr2BC7f2k4TeI",
    url: "https://raw.githubusercontent.com/0xRyanC/1f916-witness/main/countersignatures.jsonl",
  }),
  Object.freeze({
    id: 8,
    operator: "liveness",
    public_key: "NgHCVDwGuYeHX0qnuOKBgufNwgu804x1ZDyTU63sJwE",
    url: "https://raw.githubusercontent.com/wyeshunf/1f916-witness/main/witness-state/countersignatures.jsonl",
  }),
]);

/**
 * Lifecycle of an entry (Seal): "anchoring each day's batch hash into an
 * external timestamping chain makes the existence proof independent of the
 * identity layer". The OpenTimestamps calendars the day's hash is offered to,
 * in order; the first that answers is the one recorded.
 *
 * Not a whitepaper list. The paper names an external chain and stops there, so
 * which calendars is the maintainer's published choice; it moves only by a
 * later decision.
 */
export const ANCHOR_CALENDARS: readonly string[] = Object.freeze([
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://alice.btc.calendar.opentimestamps.org",
  "https://bob.btc.calendar.opentimestamps.org",
  "https://finney.calendar.eternitywall.com",
]);

/**
 * Hash versioning. The normalization rule version in force at submission; every
 * hash on an entry is computed under it. norm-v1.2 is in force for entries
 * submitted on or after 2026-09-08; entries submitted before that keep the
 * version they were signed under.
 */
export const NORM_VERSION = "norm-v1.2";

/**
 * The entry schema version in force: what a new entry is written and checked
 * against, and what the offline verifier names when it meets a core sealed under
 * an older one. v0.7 is the version that carries `domain` in the signed core
 * (schema/nomankind-entry-schema.json, decision D-071).
 *
 * A format version and not a policy number, held here for the same reason
 * NORM_VERSION is: one place says which rules are in force, and every reader
 * asks that place rather than a string spelt out beside a check.
 */
export const SCHEMA_VERSION = "v0.7";

/**
 * Snapshot normalization, step 1 (Fetch). One HTTP GET follows at most five
 * redirects; a chain longer than that is not pinned, it is chased.
 */
export const FETCH_MAX_REDIRECTS = 5;

/**
 * Snapshot normalization, step 1 (Fetch). The capture times out after thirty
 * seconds, stated there as "Timeout thirty seconds" and held here in
 * milliseconds because that is the unit every timer takes.
 */
export const FETCH_TIMEOUT_MS = 30000;

/**
 * Snapshot normalization, step 2 (Archive). The largest response body the
 * Worker will archive, in bytes: ten mebibytes. A citation is a document, and a
 * body past this size is a download, not a page to pin.
 *
 * Not a whitepaper number, and not in the norm rule either: the rule says the
 * raw body is archived and leaves the ceiling to published policy. This is the
 * maintainer's own choice and it moves only by a later decision.
 */
export const CAPTURE_MAX_BYTES = 10485760;

/**
 * Request authentication (decision D-014). A signed write request carries a
 * timestamp; a request whose timestamp is more than this far from the
 * verifier's clock, in either direction, is rejected.
 *
 * Not a whitepaper number. The paper fixes the signing scheme, not the
 * operational window; this is the orchestrator's choice, recorded in the Notion
 * Decisions database.
 */
export const REQUEST_CLOCK_SKEW_SECONDS = 300;

/**
 * Request authentication (decision D-014). A verifier remembers a spent nonce
 * at least this long. Twice the skew window, so no request that the clock-skew
 * rule still accepts can be replayed after its nonce has been forgotten.
 *
 * Not a whitepaper number. The orchestrator's operational choice, recorded in
 * the Notion Decisions database.
 */
export const NONCE_RETENTION_SECONDS = 600;

/**
 * Lifecycle of an entry, Validate: "The draw is a deterministic function of a
 * public randomness beacon's output (a beacon like drand [5]), the entry id,
 * and a published snapshot of the eligible pool."
 *
 * The paper names drand and stops there, so which drand chain the draw reads is
 * the maintainer's published choice, exactly as a domain's excluded-party
 * list is (`DOMAINS`, above): it
 * moves only by a later decision, and it is pinned here rather than in the
 * adapter so an offline reader can recompute a draw years later from the same
 * chain the draw used. `chain_hash` is quicknet's, `genesis_time` its first
 * round's UNIX second and `period_seconds` its round interval, which together
 * give every round its time without asking the network.
 *
 * Not a whitepaper number. The maintainer's published policy; it moves only by
 * a later decision.
 */
export const BEACON: Readonly<{
  endpoint: string;
  beacon_id: string;
  chain_hash: string;
  genesis_time: number;
  period_seconds: number;
}> = Object.freeze({
  endpoint: "https://api.drand.sh",
  beacon_id: "quicknet",
  chain_hash:
    "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  genesis_time: 1692803367,
  period_seconds: 3,
});

/**
 * The training path, "Drift attestation": "A probe set is drawn from verified,
 * observed, fresh entries by public randomness ... That set size is published
 * policy, and the observed tier will be thin at genesis (Section 12)."
 *
 * `PROBE_SET_SIZE` is that published size: ten probes when the log holds at
 * least ten entries to draw from. `PROBE_SET_MIN_CANDIDATES` is the floor below
 * which no attestation is drawn at all, and it is one rather than ten precisely
 * because the paper says the observed tier is thin at genesis: between the floor
 * and the size every candidate is drawn, so an attestation over three probes is
 * a small attestation and never a refused one. A score over one probe says
 * little, which is what the probe count published beside every score is for.
 *
 * Not whitepaper numbers. The paper names the rule and says the size is
 * published policy, so both are the maintainer's own placeholders (M22); they
 * move only by a later decision, and never by an edit anywhere but this file.
 */
export const PROBE_SET_SIZE = 10;
export const PROBE_SET_MIN_CANDIDATES = 1;

/**
 * The training path, "Drift attestation": "Three operators from the trusted
 * pool, none under the model's operator, score its answers against the log and
 * sign the result."
 *
 * Three is the paper's own number, so this one is not a placeholder: it is the
 * sentence, held here rather than written into src/attest.ts, because a count of
 * signers is the same kind of thing as APPROVALS_TO_VERIFY_LARGE_POOL and lives
 * where every other one does.
 */
export const ATTESTATION_SCORERS = 3;

/**
 * How long an attestation stays open: from the request to the deadline for the
 * model's answers and for the scorers' scores.
 *
 * Not a whitepaper number. The paper says an attestation happens and never how
 * long it may hang open, so the window is the maintainer's own placeholder
 * (M22), seventy-two hours because that is what ASSIGNMENT_WINDOW_HOURS already
 * gives a drawn validator and a second, different window for the same kind of
 * drawn work would be a rule nobody could remember. It is its own constant all
 * the same: the two move independently, and an attestation window that borrowed
 * the assignment's number would silently move with it.
 */
export const ATTESTATION_WINDOW_HOURS = 72;

/**
 * The most records one list request returns. The first page-size number in the
 * system, so it lives here with every other published amount rather than
 * beside the query that uses it; src/storage/repository.ts holds no default
 * page size and every listing there takes the caller's explicit limit.
 *
 * Not a whitepaper number. The maintainer's published policy; it moves only by
 * a later decision.
 */
export const LIST_PAGE_LIMIT = 100;

/**
 * How many days of their own usage a key holder is shown when they name none,
 * and the most one response will show at all. Page sizes of the
 * `/keys/me/usage` window in the sense LIST_PAGE_LIMIT is: they say how much of
 * a reader's own history one response carries, never what anything costs or
 * what anybody is allowed.
 *
 * Not a whitepaper number. The maintainer's published policy; it moves only by
 * a later decision. Here rather than beside the door because every published
 * amount is here, and a page size the door kept to itself would be the one
 * number a reader could not check against `GET /policy`.
 */
export const USAGE_DAYS_DEFAULT = 30;
export const USAGE_DAYS_MAX = 90;

/**
 * How many entries the home page's "latest sealed entries" row shows. A page
 * size, so it lives here beside LIST_PAGE_LIMIT rather than inside the page that
 * renders it: src/ui/ holds no numbers of this kind and src/storage/ holds no
 * default limit at all.
 *
 * Not a whitepaper number, and not a rule: it is presentation. The maintainer's
 * published policy; it moves only by a later decision.
 */
export const HOME_LATEST_ENTRIES = 10;

/** How many seals the landing page's live seal-chain band shows. A page size, so it lives here beside HOME_LATEST_ENTRIES. */
export const LANDING_BAND_SEALS = 12;

/**
 * Incentives / Standing: "Standing is the non-monetary record of being right. It
 * is earned by approved submissions, completed validations (assigned work
 * weighted highest), rejections that hold, and upheld challenges ... Amounts and
 * rates are published policy."
 *
 * The paper names every move and states no amount, so all six below are the
 * maintainer's own placeholders, in standing units. Assigned work weighs highest
 * because the paper says so — "that is what makes an assignment on an entry
 * nobody will read worth doing" — and a rejection that holds counts the same as
 * an approval, which is why one number covers both decisions.
 *
 * Not whitepaper numbers. The maintainer's published policy (M21); they move
 * only by a later decision, and never by an edit anywhere but this file.
 */
export const STANDING_VALIDATION_VOLUNTEERED = 1;
export const STANDING_VALIDATION_ASSIGNED = 3;
export const STANDING_SUBMISSION_VERIFIED = 2;
export const STANDING_DISPUTE_UPHELD = 5;
export const STANDING_OVERTURNED_SIGNER = 5;
export const STANDING_ASSIGNMENT_MISSED = 2;

/**
 * Incentives / Standing (decision D-087): a validation or reconfirmation whose
 * signed record carries a passing n-of-k measurement earns this beside
 * STANDING_VALIDATION_ASSIGNED or STANDING_VALIDATION_VOLUNTEERED, so the
 * trusted pool tilts toward the operators who measure rather than the ones who
 * accept a test without running it (Section 4, Section 9).
 *
 * Not a whitepaper number: the maintainer's own placeholder, moving only by a
 * later decision, exactly as the six above it.
 */
export const STANDING_VALIDATION_REPRODUCED = 2;

/**
 * Incentives / Standing: a drift attestation's score, earned by the operator
 * behind the scorer that signed it.
 *
 * Section 8, Drift attestation: "three operators from the trusted pool ... score
 * its answers against the log and sign the result", and Section 9 earns standing
 * for "completed validations". Scoring an attestation is completed work of
 * exactly that kind — drawn, windowed, and burned when it goes unanswered by
 * STANDING_ASSIGNMENT_MISSED, the same burn an unanswered assignment carries —
 * so the log would be paying the miss and not the work if this number did not
 * exist.
 *
 * One rather than STANDING_VALIDATION_ASSIGNED's three because a score is a
 * smaller piece of work than a validation: the probes are drawn for the scorer
 * and the answers are already there. Not a whitepaper number: the maintainer's
 * own placeholder, moving only by a later decision, exactly as the seven above.
 */
export const STANDING_ATTESTATION_SCORED = 1;

/**
 * Incentives / Standing (decision D-095): Section 6's revalidation request —
 * "If the check finds the fact changed, the requester gets the stake back plus a
 * challenger-style reward" — is what this pays, and it pays it in standing,
 * because the stake was standing. A dispute's reward is money because a dispute
 * claws money back; a check that found the fact changed overturns nothing and
 * claws nothing back, so the reward is paid in the currency the stake was in.
 *
 * Less than STANDING_DISPUTE_UPHELD because a request carries no citation: it
 * only asks for a check, where a challenge argues the case and brings the
 * evidence. Not a whitepaper number: the maintainer's own placeholder, moving
 * only by a later decision, exactly as the eight above it.
 */
export const STANDING_REVALIDATION_CHANGED = 3;

/**
 * Incentives / Standing: standing "gates everything discretionary, from entry to
 * and stay in the trusted pool". Two numbers rather than one, because a single
 * threshold would flap: an operator sitting exactly at the bar would be trusted
 * and untrusted by turns as one burn landed and one validation followed.
 *
 * `STANDING_TRUSTED_ENTRY` is what a registered, non-maintainer, non-provider
 * operator must reach to be trusted; `STANDING_TRUSTED_STAY` is what a trusted
 * operator must stay at or above to keep it. Not whitepaper numbers: the
 * maintainer's published policy, moving only by a later decision.
 */
export const STANDING_TRUSTED_ENTRY = 10;
export const STANDING_TRUSTED_STAY = 0;

/**
 * Incentives / Standing: standing "decays when the work it came from stops being
 * read or was never used ... Decay is paused until the paid loop starts (below),
 * since before then there is nothing for it to decay against."
 *
 * So there is no rate here, and there must not be: the paper publishes the pause
 * and not a number, and inventing a rate now would be publishing a policy nobody
 * decided. The flag is what src/standing.ts reads, and the day the paid loop
 * starts it moves by a decision, together with the rate that replaces it.
 */
export const STANDING_DECAY_PAUSED = true;

/**
 * Incentives / Money: "At $0.50 per thousand paid reads, an entry read ten
 * thousand times in a month earns its submitter 75 cents and each validator 25."
 *
 * That is the paper's own worked example, so the price is the paper's: fifty
 * cents per thousand reads is five hundred micro-USD per read. Micro-USD (a
 * millionth of a dollar) is the unit every read-revenue amount in the ledger is
 * counted in, because a single read's share is 75 micros — a fraction of a cent,
 * and a ledger that rounded it to cents would pay nobody anything.
 *
 * A price, not a rule, and the paper says the unit economics depend on API
 * pricing that does not exist yet: the maintainer's published policy, moving
 * only by a later decision.
 */
export const READ_PRICE_MICROS_PER_READ = 500;

/**
 * Incentives / Money: "The log is free to read at low volume, forever. Revenue
 * comes from high-rate API access, structured feeds and webhooks, change
 * alerts."
 *
 * A tier is a daily cap and nothing else. The free tier is the paper's "free to
 * read at low volume, forever", so it carries no key and is counted per client;
 * the paid tiers carry a key and are counted per key. Every paid read is priced
 * at READ_PRICE_MICROS_PER_READ, one number per read whatever tier bought it
 * (D-087), so a tier buys throughput and never a discount.
 *
 * The paper names the free tier and states no cap and no ladder, so all three
 * rows are the maintainer's own placeholders (M24, the retrospective's M2 rule)
 * and move only by a later decision.
 */
export interface RateTier {
  /** The display name: what the tiers table and the checkout page show. */
  readonly name: string;
  /** The cap per UTC day, per key on a paid tier and per client on the free one. */
  readonly reads_per_day: number;
  /** False: served without a key at all. */
  readonly key: boolean;
}

export const RATE_TIERS: Readonly<Record<string, RateTier>> = Object.freeze({
  free: Object.freeze({ name: "Free", reads_per_day: 1_000, key: false }),
  standard: Object.freeze({
    name: "Standard",
    reads_per_day: 100_000,
    key: true,
  }),
  high: Object.freeze({ name: "High", reads_per_day: 1_000_000, key: true }),
});

/** The slug of the tier a reader gets without asking for anything. */
export const FREE_TIER = "free";

/** Whether a slug names a registered tier that a key is bought for. */
export function isPaidTier(slug: unknown): slug is string {
  if (typeof slug !== "string") return false;
  const tier = RATE_TIERS[slug];
  return tier !== undefined && tier.key;
}

/**
 * Incentives / Money: "The contributor share is a floor that only rises."
 *
 * So the floor is a published number of its own rather than a comment on
 * CONTRIBUTOR_SHARE_PERCENT: a share that may only rise needs something to be
 * checked against, and test/policy.test.ts checks it — the share is at or above
 * the floor, and it is exactly the split it is made of.
 */
export const CONTRIBUTOR_SHARE_FLOOR_PERCENT = 30;

/**
 * Decision D-078: the paid loop runs over Stripe in test mode from the start,
 * spoken to over its REST API with `fetch` and signed webhooks, with no SDK.
 *
 * The provider's fixed strings, held here for the reason MIRROR and REGISTRY
 * are: an address the system depends on is a published choice, not an adapter's
 * private detail. No number here is a price and nothing here is a secret — the
 * key and the webhook signing secret are Worker secrets (D-016) and never
 * appear in this repository.
 */
export const STRIPE: Readonly<{
  api: "https://api.stripe.com";
  meter_event_name: "nomankind_read";
  price_lookup_prefix: "nomankind-";
  currency: "usd";
  webhook_tolerance_seconds: 300;
  webhook_path: "/stripe/webhook";
}> = Object.freeze({
  api: "https://api.stripe.com",
  meter_event_name: "nomankind_read",
  /** A price's lookup_key is `${prefix}${environment}-${tier}`. */
  price_lookup_prefix: "nomankind-",
  currency: "usd",
  /** How far a webhook's own timestamp may sit from now before it is stale. */
  webhook_tolerance_seconds: 300,
  webhook_path: "/stripe/webhook",
} as const);

/**
 * Incentives / Money: change alerts are a paid feature. How many endpoints one
 * key may hold, how long a delivery may take, and when a failed delivery is
 * tried again.
 *
 * None of the four is in the paper, which names the feature and no amount: the
 * maintainer's published policy (M24), moving only by a later decision. The
 * retry ladder is minutes from the attempt that failed — attempt n (1-based)
 * schedules the next at now + ALERT_RETRY_MINUTES[n - 1], and past the last
 * entry the delivery is failed rather than retried forever.
 */
export const ALERT_ENDPOINTS_PER_KEY = 5;
export const ALERT_TIMEOUT_MS = 10_000;
export const ALERT_RETRY_MINUTES: readonly number[] = Object.freeze([
  5, 30, 120, 720, 1440,
]);

/**
 * What a change alert can be about: the seven moments in an entry's life a
 * subscriber is told about. Every one of them is a fact already in the sealed
 * log, so an alert is a notification of something public and never a fact of
 * its own — `stale` included, which is the moment an entry's confirmation
 * window closed with no reconfirmation and the sweep marked it stale.
 */
export const ALERT_KINDS = Object.freeze([
  "submitted",
  "verified",
  "rejected",
  "reconfirmed",
  "superseded",
  "overturned",
  "stale",
] as const);

export type AlertKind = (typeof ALERT_KINDS)[number];

/**
 * Incentives / Money, as amended by decision D-053: payouts are batched per
 * operator on a monthly cycle, and an operator whose released accruals sit below
 * the published minimum is not paid that cycle — the amount carries forward to
 * the next one.
 *
 * Five dollars, in the micro-USD the ledger counts in. Neither number is in the
 * paper: the paper says payouts happen and leaves the cadence and the floor to
 * published policy, so both are the maintainer's own (D-053) and move only by a
 * later decision. The minimum exists because a transfer costs more than a
 * long-tail entry earns in a month, and a payout that cost more than it paid
 * would take the difference out of the contributor pool.
 */
export const PAYOUT_MINIMUM_MICROS = 5_000_000;

/**
 * The payout cycle (D-053): one UTC calendar month. A name and not a number,
 * held here with every other published amount because it is the same kind of
 * thing — a published choice the ledger reads and nobody else may restate.
 */
export const PAYOUT_CYCLE = "monthly";

/**
 * Section 11, "Deployment and status": the sealed log is exported daily to a
 * public repository under CC0, so a fork does not have to ask nomankind for the
 * record — "the exit is not a promise, it is a copy".
 *
 * Which repository, on which branch, through which API, and under which
 * license. Pinned here rather than in the mirror adapter for the same reason
 * REGISTRY and WITNESS_PIN are: a reader holding a clone years from now has to
 * be able to say which repository it came from and what it was published under
 * without running the Worker.
 *
 * Not a whitepaper list, and no number: the paper names the daily export and the
 * CC0 posture and stops there, so the addresses are the maintainer's published
 * choice (M23) and move only by a later decision. The credential that writes to
 * it is never here — it is the MIRROR_TOKEN secret (D-016).
 */
export const MIRROR: Readonly<{
  repository: string;
  branch: string;
  api: string;
  web: string;
  raw: string;
  license: string;
}> = Object.freeze({
  repository: "nomankind-ai/log",
  branch: "main",
  api: "https://api.github.com",
  web: "https://github.com",
  raw: "https://raw.githubusercontent.com",
  license: "CC0-1.0",
});

/** Every policy number, collected and frozen. */
export const POLICY = Object.freeze({
  TRUSTED_POOL_SWITCH,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  APPROVALS_TO_VERIFY_LARGE_POOL,
  REJECTIONS_TO_REJECT,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
  ASSIGNMENT_WINDOW_HOURS,
  REPRODUCTION_RUNS,
  REPRODUCTION_HOLDS,
  DOMAINS,
  HOLDBACK_DAYS,
  READ_SHARE_SPLIT,
  SLOT_COUNT,
  CONTRIBUTOR_SHARE_PERCENT,
  SEAL_INTERVAL_MINUTES,
  SWEEP_INTERVAL_MINUTES,
  STATUS_ATTENTION_AFTER_INTERVALS,
  STATUS_FAILING_AFTER_MINUTES,
  WITNESSES_REQUIRED,
  SEAL_MAX_EVENTS,
  WITNESS_FILE_TAIL_BYTES,
  REGISTRY,
  WITNESS_PIN,
  ANCHOR_CALENDARS,
  FAILURE_REPORT_THRESHOLD,
  DISPUTE_STAKE_STANDING,
  DISPUTE_FILING_FEE_CENTS,
  REVALIDATION_REQUEST_STAKE_STANDING,
  REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW,
  STANDING_VALIDATION_VOLUNTEERED,
  STANDING_VALIDATION_ASSIGNED,
  STANDING_SUBMISSION_VERIFIED,
  STANDING_DISPUTE_UPHELD,
  STANDING_OVERTURNED_SIGNER,
  STANDING_ASSIGNMENT_MISSED,
  STANDING_VALIDATION_REPRODUCED,
  STANDING_ATTESTATION_SCORED,
  STANDING_REVALIDATION_CHANGED,
  STANDING_TRUSTED_ENTRY,
  STANDING_TRUSTED_STAY,
  STANDING_DECAY_PAUSED,
  READ_PRICE_MICROS_PER_READ,
  RATE_TIERS,
  FREE_TIER,
  CONTRIBUTOR_SHARE_FLOOR_PERCENT,
  STRIPE,
  ALERT_ENDPOINTS_PER_KEY,
  ALERT_TIMEOUT_MS,
  ALERT_RETRY_MINUTES,
  ALERT_KINDS,
  PAYOUT_MINIMUM_MICROS,
  PAYOUT_CYCLE,
  MIRROR,
  NORM_VERSION,
  SCHEMA_VERSION,
  FETCH_MAX_REDIRECTS,
  FETCH_TIMEOUT_MS,
  CAPTURE_MAX_BYTES,
  REQUEST_CLOCK_SKEW_SECONDS,
  NONCE_RETENTION_SECONDS,
  PROBE_SET_SIZE,
  PROBE_SET_MIN_CANDIDATES,
  ATTESTATION_SCORERS,
  ATTESTATION_WINDOW_HOURS,
  LIST_PAGE_LIMIT,
  USAGE_DAYS_DEFAULT,
  USAGE_DAYS_MAX,
  HOME_LATEST_ENTRIES,
  LANDING_BAND_SEALS,
  BEACON,
});

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

// ---------------------------------------------------------------------------
// Two paths to being a validator, one registry (decision D-138)
// ---------------------------------------------------------------------------

/**
 * The two kinds of operator, and the one thing they have in common: a key
 * publicly bound to something the world can check.
 *
 * `domain` is everything that existed before D-138 — a TXT record under a DNS
 * name, a signed attestation, standing, the trusted pool. `community` is a key
 * bound to an account on an agent community, registered implicitly by its first
 * counted confirmation line that carries the attestation token, so there is no
 * form, no domain and no registration door to walk through. One registry holds
 * both, because validation is one thing and the record should say so.
 */
export const OPERATOR_KINDS = Object.freeze(["domain", "community"] as const);

export type OperatorKind = (typeof OPERATOR_KINDS)[number];

/**
 * How a key may be bound to a public identity, an open list.
 *
 * `registry`: a key-bind in a registry whose log the pinned witnesses
 * countersign (1F916 today). Counts.
 * `profile`: the public key published on the agent's public profile on its
 * community, captured and sealed exactly as a citation is. Counts.
 * `platform`: a platform's statement about an account. Shown, never counted —
 * it is somebody else's assertion, not a proof anyone can recheck offline.
 *
 * A bare key never counts, whatever it signs: the point of a binding is that
 * the world can see whose key it is.
 */
export const BINDING_KINDS = Object.freeze([
  "registry",
  "profile",
  "platform",
] as const);

export type BindingKind = (typeof BINDING_KINDS)[number];

/** The binding kinds a counted validation may rest on. */
export const COUNTING_BINDING_KINDS: readonly BindingKind[] = Object.freeze([
  "registry",
  "profile",
]);

/**
 * The Sybil floor for a consensus met by community operators alone: three
 * distinct bound accounts.
 *
 * A domain operator costs a DNS name and a signed attestation; an account on an
 * agent community costs much less, so a consensus that rests on accounts alone
 * is asked for more distinct accounts than a consensus with a domain operator
 * in it. Not a whitepaper number: the maintainer's published choice under
 * D-138, and it moves only by a later decision.
 */
export const COMMUNITY_MIN_ACCOUNTS = 3;

/**
 * And from how many distinct communities, once more than one community counts.
 *
 * Enforced only while `countingCommunities()` holds more than one venue: a rule
 * demanding two communities in a world with one would refuse every community
 * consensus there could be, which is a moratorium and not a Sybil rule.
 */
export const COMMUNITY_MIN_COMMUNITIES = 2;

/**
 * How many community validations of one entry may be counted from one
 * community.
 *
 * With one counting community the cap is the whole consensus — there is nowhere
 * else for a validation to come from, and the account floor above is what
 * carries the weight. Once two communities count, the cap falls to
 * `VERIFICATION_MIN_OUTSIDE_OPERATORS - COMMUNITY_MIN_COMMUNITIES + 1`, so one
 * board can never supply a consensus by itself: the last seat has to come from
 * somewhere else.
 */
export function communityCapPerEntry(countingCommunities: number): number {
  if (isSingleCountingCommunity(countingCommunities)) {
    return VERIFICATION_MIN_OUTSIDE_OPERATORS;
  }
  return VERIFICATION_MIN_OUTSIDE_OPERATORS - COMMUNITY_MIN_COMMUNITIES + 1;
}

/**
 * Whether the world still has only one counting community.
 *
 * The one place that sentence is decided. Two rules read it — the cap above,
 * and the `COMMUNITY_MIN_COMMUNITIES` floor in src/derive.ts — and a rule
 * spelled out twice is a rule that can be changed once: a floor that went on
 * demanding two communities after the cap stopped assuming one would refuse
 * every community consensus there could be.
 */
export function isSingleCountingCommunity(
  countingCommunities: number = countingCommunityCount(),
): boolean {
  return countingCommunities <= 1;
}

/** How many communities count today (`countingCommunities().length`). */
export function countingCommunityCount(): number {
  return countingCommunities().length;
}

/**
 * What an entry discloses about who met its consensus, weakest first.
 *
 * `registered` when domain operators alone met it, `mixed` when domain
 * operators took part but community operators were needed to reach it, and
 * `community` otherwise. The order is the order of the `min_class` filter on
 * the read doors: `min_class=mixed` admits mixed and registered.
 *
 * Sealed history, not a rating: the class is derived from the validators
 * counted at the decision seal and is never relabelled by later evidence. A
 * reconfirmation by a domain operator is an additive dated layer instead.
 */
export const VERIFICATION_CLASSES = Object.freeze([
  "community",
  "mixed",
  "registered",
] as const);

export type VerificationClass = (typeof VERIFICATION_CLASSES)[number];

/**
 * The token that turns a public confirmation into a validation.
 *
 * A confirmation line carrying `attest:<version>` is its author's signature
 * over this record's independence attestation at that version, said once, in
 * the line itself — which is how a community operator attests with no form and
 * no registration door (D-138 item 1). A line without it stays what D-136 made
 * it: a public confirmation, shown, clearing the bootstrap label, counted
 * toward no status.
 */
export const CONFIRMATION_ATTESTATION_TOKEN_PREFIX = "attest:";

/**
 * The token that carries the author's own signature over the line.
 *
 * A venue with a `profile` binding signs nothing on the author's behalf: the
 * board attributes a comment to an account and stops there. So the author signs
 * the canonical line itself and writes the signature into the line, last of the
 * tokens and before the free text — `sig:<base64url Ed25519 signature>` — and
 * the key it is by is the one their public profile publishes (D-138 item 2).
 *
 * The token is never part of what is signed: the canonical line is the claim,
 * and a signature cannot be inside its own preimage.
 */
export const CONFIRMATION_SIGNATURE_TOKEN_PREFIX = "sig:";

/**
 * How a key is published on a profile: this word, then the key.
 *
 * The one thing a `profile` binding looks for in the bytes it captured. Spelled
 * with this record's own name so a profile can carry it beside whatever else
 * its author writes, and read as the FIRST occurrence and no other: a profile
 * naming two keys has published one key and something else, and guessing which
 * would be the door choosing an identity for somebody.
 */
export const PROFILE_KEY_PREFIX = "nomankind-key:";

/**
 * Lifecycle of an entry. An assigned validator has seventy-two hours to
 * respond; a miss costs standing and the next beacon round draws a replacement.
 */
export const ASSIGNMENT_WINDOW_HOURS = 72;

/**
 * Lifecycle of an entry. How old a draft may be, counted from its
 * `submitted_at` to the run's own clock, and still be drawn a validator.
 *
 * The QA of 2026-09-12: the sweep's draws step paged every draft in the table
 * on every run, so a draft nobody ever validated stayed in the working set
 * forever and every run paid for it again — a cost that grows with the log and
 * is spent on entries the log has already given up drawing for.
 *
 * A bound on the queue and not a status: an abandoned draft is still a draft,
 * it is still in the log, it is still readable, and a volunteer may still
 * validate it. What it stops getting is a draw. Nothing about this is
 * recomputed onto the row and nothing derives from it — the rule is read at
 * run time against the run's clock, so moving the number moves the queue and
 * rewrites no history.
 *
 * The paper names no cutoff, so this is the maintainer's own placeholder (M25,
 * the retrospective's M2 rule), moving only by a later decision.
 */
export const DRAW_DRAFT_MAX_AGE_DAYS = 30;

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
  // ai-ecosystem, and `correction` every domain (the QA of 2026-09-12)
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
  /**
   * The UTC date this domain was registered, as the registry document states it
   * (schema/nomankind-domain-registry-v1.md).
   *
   * Here because senior standing buys early access to a newly registered domain
   * for `DOMAIN_EARLY_ACCESS_DAYS` (D-130, D-131 item 2), and "newly" is a
   * question about a date the table did not carry. A published date and not a
   * derived one: the registration of a domain is a decision the maintainer
   * publishes, not an event in the log, so the table is where it lives.
   */
  readonly registered_at: string;
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
  // The record's own date: the first domain was registered with the record
  // itself, and there was no other until D-096.
  registered_at: "2026-09-02",
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
          // Decision D-134: Microsoft publishes its AI conduct and model
          // commitments under a second registrable domain, so a citation on it
          // is as official as one on microsoft.com. Listed rather than
          // pattern-matched, like every host here: an authority's official set
          // is what the maintainer published, never what a suffix suggests.
          "microsoft.ai",
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
  // Decision D-096, 2026-09-11, exactly as the registry document states it.
  registered_at: "2026-09-11",
  categories: Object.freeze([
    "in_force",
    "amended",
    "repealed",
    "guidance_issued",
    "enforcement_action",
    // The challenge (the QA of 2026-09-12, a D-096 gap). A challenge is filed
    // as a correction entry in the domain of the entry it challenges, so a
    // domain without this row is a domain whose record cannot be disputed at
    // all: the submission dies `category_not_in_domain` and `overturned_by`
    // and the unlearn signal are unreachable in it. ai-ecosystem's row,
    // unchanged -- a correction happened, so it carries no window, no
    // transcript and no official source.
    "correction",
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
    // A correction happened, exactly as ai-ecosystem's does.
    correction: null,
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
    // a regulator, which the recognized list covers. Neither is a correction,
    // for ai-ecosystem's reason: the rule that binds a challenge is the one
    // its target carries, which the dispute door checks against the challenged
    // entry's own domain and category.
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
  // Decision D-096, 2026-09-11, exactly as the registry document states it.
  registered_at: "2026-09-11",
  categories: Object.freeze([
    "commitment_published",
    "commitment_changed",
    "commitment_withdrawn",
    "conduct_observed",
    "refusal_behavior",
    "filter_behavior",
    "safety_eval",
    "incident",
    // The challenge (the QA of 2026-09-12, a D-096 gap), exactly as
    // ai-governance's: a challenge is filed as a correction entry in the domain
    // of the entry it challenges, and a domain without this row is a domain
    // whose record cannot be disputed. ai-ecosystem's row, unchanged -- no
    // window, no transcript, no official source, and neither the disclosure nor
    // the version-staleness rule, which are about what a system does.
    "correction",
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
    // A correction happened, exactly as ai-ecosystem's does.
    correction: null,
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
    // not: they are what somebody else found. Nor is a correction, for
    // ai-ecosystem's reason: the rule that binds a challenge is the one its
    // target carries, which the dispute door checks against the challenged
    // entry's own domain and category.
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
 * Incentives / Money. The holdback an accrued fee waited out while the record
 * was sold. Nothing accrues any more (D-127); it is published because it is the
 * one number a reader still needs to read an old ledger row.
 */
export const HOLDBACK_DAYS = 30;

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
 * dispute for free."
 *
 * One stake, in standing, and no fee of any kind (decision D-127, "no money
 * anywhere"). The paper's second half — "a bare key stakes a refundable filing
 * fee" — is superseded: there is no money in this record to stake, so what a
 * filing puts up is contribution, which is the only currency there is. A bare
 * key has no standing to put up and therefore cannot file at all; the dispute
 * door refuses it with the refusal it already had for an operator that cannot
 * cover the stake, `insufficient_standing` (src/dispute.ts).
 *
 * The paper names the rule and states no amount, so the amount below is the
 * maintainer's own placeholder (decision D-064), in standing units. It moves
 * only by a later decision.
 */
export const DISPUTE_STAKE_STANDING = 10;

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
 * longer than this is not dropped: the seal takes the first two hundred and the
 * next run continues from where it stopped, so the chain stays contiguous.
 *
 * Not a whitepaper number, and not a rule: it is operational, a ceiling on the
 * work one sweep does and on the size of one Merkle batch. A published
 * placeholder of the maintainer's own — two hundred, because a seal's writes
 * are one statement per entry it covers and the sweep has five minutes to make
 * them, so the ceiling is set where one run's work comfortably fits rather than
 * where D1 gives out. It moves only by a later decision.
 */
export const SEAL_MAX_EVENTS = 200;

/**
 * The most statements one D1 batch may carry.
 *
 * An operational limit rather than a rule of the record: it says nothing about
 * what anyone may do or what anything costs, only the size a write is cut into
 * so that a seal covering SEAL_MAX_EVENTS entries reaches the database as
 * several safe batches instead of one it may refuse. A hundred, which is the
 * size D1 is known to take.
 *
 * Published like every other constant here all the same — it lives in this
 * module and on the policy page, because the rule is that every number the
 * kernel reads is one a reader can look up, whether or not it is a rule.
 */
export const SWEEP_BATCH_STATEMENTS = 100;

/**
 * Incentives / Money, Section 9: "Each day's published count is the number the
 * seal commits to." How many of a published day's entries one run of the ledger
 * step walks.
 *
 * Not a whitepaper number and not a rule about money: what a day is worth does
 * not depend on it. Pricing one entry is a read of the entry and a read per
 * read-share slot it seated, so a day on which a thousand entries were read is
 * thousands of statements, and a run that tried them all would be killed
 * part-way through a day rather than finish it. A published placeholder of the
 * maintainer's own — twenty, which leaves room for the rest of the sweep in one
 * alarm — and the day is not dropped: the next run resumes the same day where
 * this one stopped, and the day's reconciliation is written only once every
 * entry of it has been priced. It moves only by a later decision.
 */
export const LEDGER_ENTRIES_PER_RUN = 20;

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
 * The bar in full, as the paper publishes it: a published key, no two under
 * common control, nomankind ineligible to be one, and no pinned witness may be
 * an operator of the record or under the control of one (decision D-121). The
 * last clause is the one a reader of this list would otherwise have to take on
 * trust — a witness set drawn from the validators is the failure a witness set
 * exists to catch — so the two sets and their intersection are published at
 * /independence rather than only asserted here. What that page can check is the
 * intersection; control beyond it is a claim the maintainer makes and not a
 * proof, which is what "Limitations" already says about this dependency.
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
 * The public-confirmation door (decision D-136): where a confirmation may be
 * said, and by whom the batch threads are posted.
 *
 * Whitepaper Section 11's genesis is a bootstrap exception "stated as such",
 * and the way out of it is somebody outside the maintainer's own perimeter
 * checking a fact in public. A venue is only usable for that when a statement
 * made there carries a key the founding registry witnessed — which is what
 * separates the two kinds of venue below.
 *
 * `citizen` is the handle whose posts are the batch threads. Every post by that
 * citizen is a batch thread once the board's API lists it (it does:
 * `GET /api/citizen/<handle>` answers that citizen's own posts), so M25g's
 * daily batch posts need no deploy. `threads` is the pinned floor per
 * environment, kept for two reasons: a board that stops listing posts still has
 * the threads the maintainer pinned by decision, and production names none
 * until the first production batch post exists.
 *
 * Not a whitepaper list. The maintainer's published choice; it moves only by a
 * later decision.
 */
export interface ConfirmationVenue {
  /** The venue's name, as the sealed event's `venue` spells it. */
  readonly venue: string;
  /**
   * The origin every door below is read from.
   *
   * Here rather than in the adapter (decision D-138 item 2): a venue table
   * that named a board without saying where it is would be a table a reader
   * could not check, and the adapters are the code that speaks each surface
   * rather than the record of which surfaces there are.
   */
  readonly origin: string;
  /** The citizen whose posts are this venue's batch threads. */
  readonly citizen: string;
  /**
   * The repository a venue's threads live in, `owner/name`, or null for a venue
   * whose threads are a citizen's own posts.
   */
  readonly repository: string | null;
  /**
   * The threads pinned per environment, whatever the board lists.
   *
   * A thread id is whatever the venue calls one: an integer on the 1F916 board
   * and on a GitHub issue, a UUID on The Colony. It is only ever a key and a
   * path segment here, never arithmetic.
   */
  readonly threads: Readonly<Record<string, readonly (string | number)[]>>;
  /** Whether the board's API can list the citizen's posts (it can, here). */
  readonly discover: boolean;
  /**
   * How a key is bound to an account at this venue (decision D-138).
   *
   * The counting rule is per kind and not per venue: a `registry` binding is a
   * key-bind in a registry whose log the pinned witnesses countersign, a
   * `profile` binding is the key published on the agent's own public profile
   * and captured like a citation, and both count. A `platform` binding is a
   * platform's statement about an account: shown, never counted, because
   * nobody can recheck it years later without asking the platform again.
   */
  readonly binding: BindingKind;
  /**
   * The public door that answers one account's profile, or null where the venue
   * has none (decision D-138 item 2).
   *
   * `{handle}` is replaced with the comment author's handle, percent-encoded.
   * A `profile` binding is read out of whatever that door answers: the bytes
   * are captured content-addressed exactly as a citation's snapshot is, and the
   * key is the `nomankind-key:<base64url>` those bytes carry.
   */
  readonly profile_door: string | null;
  /**
   * The public door that answers one thread's comments.
   *
   * `{thread}` is the thread id, percent-encoded, `{repository}` the repository
   * above, and `{limit}` the page size the run asks for. Bounded and public on
   * both venues, so the hourly read is one request per thread.
   */
  readonly comments_door: string;
}

export const CONFIRMATION_VENUES: readonly ConfirmationVenue[] = Object.freeze([
  Object.freeze({
    venue: "1f916",
    origin: REGISTRY.origin,
    citizen: "nomankind",
    repository: null,
    threads: Object.freeze({
      demo: Object.freeze([5212]),
      production: Object.freeze([]),
      local: Object.freeze([]),
    }),
    discover: true,
    // The founding registry's own key-bind, under a witnessed head: the first
    // counting binding this record had (D-138 item 2).
    binding: "registry",
    // The registry binds the key itself, so there is no profile to read: the
    // record door (`/api/record/<handle>`) is the binding, and the adapter
    // reads it through `BoardAdapter.record`.
    profile_door: null,
    comments_door: "/api/post/{thread}",
  }),
  Object.freeze({
    venue: "colony",
    origin: "https://thecolony.ai",
    citizen: "nomankind",
    repository: null,
    threads: Object.freeze({
      // The maintainer's own post, read on 2026-09-17:
      // https://thecolony.ai/posts/09ed63ba-438a-41e8-b352-f065b376106e
      demo: Object.freeze(["09ed63ba-438a-41e8-b352-f065b376106e"]),
      production: Object.freeze([]),
      local: Object.freeze([]),
    }),
    // The public API answers one user and one post's comment tree, and lists
    // neither a user's posts nor their submissions: `/api/v1/users/nomankind`
    // answers, `/api/v1/users/nomankind/posts` and `/submissions` are 404
    // (probed 2026-09-17). So the pinned threads are the whole door here, and
    // a new batch post is a deploy until that listing exists.
    discover: false,
    binding: "profile",
    profile_door: "/api/v1/users/{handle}",
    comments_door: "/api/v1/posts/{thread}/context",
  }),
  Object.freeze({
    venue: "github",
    origin: "https://api.github.com",
    citizen: "nomankind-ai",
    repository: "nomankind-ai/bootstrap",
    threads: Object.freeze({
      // https://github.com/nomankind-ai/bootstrap/issues/1
      demo: Object.freeze([1]),
      production: Object.freeze([]),
      local: Object.freeze([]),
    }),
    // The issues of one repository are listable, but which issue is a batch
    // thread is the maintainer's decision and not a property of the repository:
    // an issue anybody may open would otherwise be a thread this record reads.
    discover: false,
    binding: "profile",
    profile_door: "/users/{handle}",
    comments_door: "/repos/{repository}/issues/{thread}/comments?per_page={limit}",
  }),
]);

/**
 * The venues a community validation may be counted from: the venues whose
 * binding kind counts (decision D-138).
 *
 * A function rather than a list, because it is a reading of the venue table and
 * a second list would be a second place for the two to disagree. Every Sybil
 * rule below is stated in terms of how many of these there are: with one
 * counting community the per-entry cap is the whole consensus, and with two the
 * cap falls so that no single board can supply a consensus by itself.
 */
export function countingCommunities(): readonly string[] {
  return CONFIRMATION_VENUES.filter((venue) =>
    COUNTING_BINDING_KINDS.includes(venue.binding),
  ).map((venue) => venue.venue);
}

/**
 * The venues where a statement is an account's word and nothing more.
 *
 * Empty since decision D-138 item 2, and kept rather than deleted because the
 * sentence it made is still the record's: The Colony and GitHub were listed
 * here while an account on them was the only thing a comment there proved.
 * They are not listed now, because a comment there may carry a signature by a
 * key the author published on its own profile — which is a `profile` binding,
 * captured and rechecked offline, and which counts.
 *
 * What has not changed is the reading of a comment that carries no such
 * signature. It is an account statement wherever it is said: sealed as a
 * `public_confirmation` with `counted` false, shown, counting towards nothing.
 * That is a fact about the line rather than about the venue, which is why the
 * list below no longer needs to name anybody.
 */
export const ACCOUNT_STATEMENT_VENUES: readonly string[] = Object.freeze([]);

/**
 * The first word of the one line the door reads (decision D-136).
 *
 * A comment on a batch thread is untrusted text written by strangers. The door
 * reads it line by line and acts on exactly the lines that begin with this
 * word in the published form
 * `nomankind-confirm-v1 <entry id> <approve|reject> <sha256:<hex>|span-present|span-absent> [reason]`;
 * everything else on the thread is prose it ignores. A format constant rather
 * than a rule, and versioned so a second form can be added without the first
 * one becoming ambiguous.
 */
export const CONFIRMATION_FORM_PREFIX = "nomankind-confirm-v1";

/**
 * The most characters of a confirmation's reason the door keeps.
 *
 * The rest of the line is a stranger's free text: it is stored, shown escaped,
 * and never followed, so the only thing bounding it protects is the size of
 * what the log carries forever. Two hundred and eighty, the length of one
 * public sentence. Not a whitepaper number; it moves only by a later decision.
 */
export const CONFIRMATION_REASON_MAX_CHARS = 280;

/**
 * The most bytes one read of the board may hold.
 *
 * The board is somebody else's server and its answers are somebody else's
 * bytes, so the door reads a bounded amount of them, exactly as a snapshot
 * capture (`CAPTURE_MAX_BYTES`) and a witness file (`WITNESS_FILE_TAIL_BYTES`)
 * are bounded. A thread bigger than this is refused rather than held: two
 * mebibytes is far more than a page of comments, and far less than a Worker.
 *
 * Not a whitepaper number; operational, and it moves only by a later decision.
 */
export const BOARD_READ_MAX_BYTES = 2097152;
/**
 * How many confirmations one sweep run may seal, across every thread.
 *
 * Operational, like every other per-run ceiling here: the door reads a public
 * board, and a thread somebody floods must cost one bounded run rather than an
 * unbounded one. Nothing is dropped — each thread's cursor stays where the run
 * stopped and the next run carries on from there.
 */
export const CONFIRMATIONS_PER_RUN = 20;

/**
 * How many entries one batch post names, when the command line does not say.
 *
 * Decision D-136 item 6: the record asks in public for its drafts to be
 * checked, and a batch is however much it has to ask about — bounded, so one
 * day's post cannot become a dump of the whole log. Nothing is refused because
 * of this number and no rule of the record depends on it; it is here because
 * every number the maintainer chose is here, and a number chosen inside a
 * command is a number nobody can find.
 */
export const BATCH_ASK_LIMIT = 150;

/**
 * How many pages of the draft listing one batch run reads before it stops.
 *
 * The same kind of bound the sweep's own reads have: a run asks a bounded
 * amount of a growing log and leaves the rest to the next one.
 */
export const BATCH_READ_PAGES_MAX = 8;

/**
 * How many comments one run reads from one thread before it stops.
 *
 * The same ceiling from the other end: a run reads a bounded page of each
 * thread past its cursor, seals what it can of it, and leaves the rest to the
 * next run.
 */
export const CONFIRMATION_COMMENTS_PER_THREAD = 100;

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
 * The most entry URLs one `/sitemap.xml` carries (decision D-114).
 *
 * A page size of the same kind as the three above — it says how much of the log
 * one document points a crawler at, never what anything costs or what anybody is
 * allowed — and the bound that keeps a sitemap from growing with the log: a
 * document that listed every entry would be a read of the whole table dressed as
 * a file, and the newest SITEMAP_MAX_ENTRIES submissions are what a crawler that
 * comes back daily actually needs.
 *
 * A placeholder for the maintainer: five thousand is the sitemaps.org protocol's
 * own bound divided by ten, chosen so the document stays well inside the format's
 * limits with no second number here for its size. Not a whitepaper number. The
 * maintainer's published policy; it moves only by a later decision.
 */
export const SITEMAP_MAX_ENTRIES = 5000;

/**
 * How long an anonymous page may be served from the edge cache, and how long
 * past that a stale copy may be served while a fresh one is fetched.
 *
 * Presentation numbers of the same kind as the page sizes above: they say how
 * far behind the log a *page* may be, never what anything costs or what anybody
 * is allowed. Sixty seconds because the sweep's own cadence is coarser than
 * that, so a reader refreshing a page is never shown a log that has moved on
 * without them for longer than a minute, and because every storage-backed page
 * costs the same reads whether one reader asks or fifty. The JSON doors are not
 * cached at all, at any number: an agent asks the log, not the edge.
 *
 * Not whitepaper numbers, and operational rather than rules of the record. The
 * maintainer's published policy; they move only by a later decision.
 */
export const PAGE_CACHE_SECONDS = 60;
export const PAGE_CACHE_STALE_SECONDS = 300;

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
 * The three tiers standing gates participation by, weakest first (D-130).
 *
 * "Standing is an asset": public, named, and what it buys is said out loud
 * rather than left to whoever is reading the table. `probation` is every
 * operator below `STANDING_TRUSTED_ENTRY` and every bare key — it may volunteer
 * validations and submit at the probationary write cap, and it is not in the
 * draw, files no disputes and asks for no revalidations. `established` is a
 * trusted operator at or above that bar: the full write cap, the draw, disputes,
 * revalidation requests, domain joins. `senior` is a trusted operator at or
 * above `STANDING_SENIOR`: a higher write cap, early access to a newly
 * registered domain, and the vote.
 *
 * Derived and never stored, exactly as standing itself is (src/standing.ts,
 * `tierOf`): a tier is a reading of a number the log produces, so standing that
 * falls drops the tier in the same run that recomputed it.
 */
export const TIERS = Object.freeze([
  "probation",
  "established",
  "senior",
] as const);

export type Tier = (typeof TIERS)[number];

/**
 * The standing a trusted operator reaches to be senior (decision D-131 item 2).
 *
 * Five times `STANDING_TRUSTED_ENTRY`: far enough above the trusted bar that a
 * senior operator has a body of work behind it rather than one good week, and
 * near enough that the tier is reachable by validating. Not a whitepaper
 * number — Section 9 gates "everything discretionary" on standing and names no
 * amount — so this is the maintainer's published policy, moving only by a later
 * decision, like every other standing number above it.
 */
export const STANDING_SENIOR = 50;

/**
 * How long a newly registered domain is open to senior operators alone
 * (decision D-131 item 2).
 *
 * D-130's recognition in its one practical form: the operators that carried the
 * record get first sight of a domain nobody has entries in yet. Fourteen days
 * from the domain's `registered_at`, after which the domain is open to every
 * established operator and the window is never reopened.
 */
export const DOMAIN_EARLY_ACCESS_DAYS = 14;

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
 * The release window, and it is zero: the record is free (decision D-127).
 *
 * Every event and every entry is released the moment it is sealed, its content
 * public and CC0 from that instant, in the mirror and served to anyone who
 * asks. The proof was always public from the first minute and still is: every
 * hash, seal, anchor, operator record, and every entry's id, domain, subject,
 * category, status, effective tier, entry hash, seal object, signers and
 * release date.
 *
 * Zero, and the arithmetic behind it is gone: D-127 item 1 removed the withhold
 * paths, so there is no code left that could hold a payload back. The number
 * stays because it is published — `mirror.json` carries
 * `release_window_days` in every v1, v2 and v3 clone, and `verify-mirror` reads
 * that column — so a reader of a directory is told what it was built under.
 * Nothing computes from it.
 *
 * This supersedes D-101's thirty days, and the whitepaper's Money section until
 * v1.7 rewrites it. It moves only by a later decision.
 */
export const RELEASE_WINDOW_DAYS = 0;

/**
 * Incentives / Money: "The log is free to read at low volume, forever. Revenue
 * comes from high-rate API access, structured feeds and webhooks, change
 * alerts."
 *
 * A tier is a daily cap and nothing else, and since D-127 that is all it has
 * ever been able to be: no read is priced anywhere in this record, so a tier
 * buys nothing at all. The free tier is the paper's "free to read at low
 * volume, forever", so it carries no key and is counted per client; the keyed
 * tiers carry a key and are counted per key. A cap, never a charge.
 *
 * The paper names the free tier and states no cap and no ladder, so all three
 * rows are the maintainer's own placeholders (M24, the retrospective's M2 rule)
 * and move only by a later decision.
 */
export interface RateTier {
  /** The display name: what the tiers table shows. */
  readonly name: string;
  /** The cap per UTC day, per key on a paid tier and per client on the free one. */
  readonly reads_per_day: number;
  /** False: served without a key at all. */
  readonly key: boolean;
}

export const RATE_TIERS: Readonly<Record<string, RateTier>> = Object.freeze({
  free: Object.freeze({ name: "Free", reads_per_day: 200, key: false }),
  standard: Object.freeze({
    name: "Standard",
    reads_per_day: 100_000,
    key: true,
  }),
  high: Object.freeze({ name: "High", reads_per_day: 1_000_000, key: true }),
});

/** The slug of the tier a reader gets without asking for anything. */
export const FREE_TIER = "free";

/**
 * Incentives / Money: "free to read at low volume, forever" is a promise about
 * a reader, and this is the promise the log makes to itself about all of them
 * at once.
 *
 * The QA of 2026-09-12: the free tier is counted per client address, so a
 * hundred addresses at the per-client cap were the whole account's daily
 * request budget and the free tier had no ceiling at all — the per-client cap
 * bounded one reader and nothing bounded the crowd. This is the ceiling: how
 * many free reads the whole log serves across every client in one UTC day,
 * counted in a scope of its own and checked before the per-client cap, so the
 * reader who crosses it is told `rate_limited` in the gate's own word rather
 * than meeting an outage.
 *
 * It bounds the free tier only. A paid key is counted against its own tier's
 * cap and a registered operator against OPERATOR_READS_PER_DAY below, and
 * neither is refused because strangers were reading: a cap that let anonymous
 * volume refuse a paying reader would sell throughput nobody could rely on.
 *
 * The paper names no ceiling, so this is the maintainer's own placeholder (M25,
 * the retrospective's M2 rule), moving only by a later decision.
 */
export const FREE_READS_PER_DAY_GLOBAL = 50_000;

/**
 * Incentives / Money, and Section 5's operators: how many reads one registered
 * operator's signed requests are served in a UTC day.
 *
 * The QA of 2026-09-12: an operator's signed read was metered in the anonymous
 * client bucket, so a validator walking the log for the entries it has to
 * reproduce spent the free tier of whatever address it happened to come from —
 * and exhausted it for every other reader behind that address. A signed request
 * names who is asking, so it is counted under that name: its own bucket, keyed
 * by operator id, with its own cap, and the free tier's ceiling above says
 * nothing about it.
 *
 * Larger than the free tier because the work is larger: the people who have to
 * reproduce an observation read more than a stranger does, and the paper asks
 * them to. A placeholder like the rows above, moving only by a later decision.
 */
export const OPERATOR_READS_PER_DAY = 10_000;

/** Whether a slug names a registered tier that a key is bought for. */
export function isPaidTier(slug: unknown): slug is string {
  if (typeof slug !== "string") return false;
  const tier = RATE_TIERS[slug];
  return tier !== undefined && tier.key;
}

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
 * What one run of the alert step may do: how many sealed events past its cursor
 * it derives alerts from, how many due deliveries it posts, and how many
 * consecutive timed-out deliveries turn an endpoint off.
 *
 * None of the three is in the paper, which names the feature and no amount: the
 * maintainer's own placeholders, published here so a subscriber can see what
 * bounds the step, and they move only by a later decision.
 *
 * Twenty events, because deriving one event's alerts re-derives a world; eight
 * deliveries, because each may take ALERT_TIMEOUT_MS and eight of those fit
 * inside one alarm with room to spare, where a hundred would not; five
 * timeouts, because an endpoint that has not answered its last five deliveries
 * is not slow but gone, and a run that kept posting to it would spend its whole
 * budget on a host nobody is listening on. A backlog is not dropped by any of
 * them: what a run does not reach, the next run does.
 */
export const ALERT_EVENTS_PER_RUN = 20;
export const ALERT_DELIVERIES_PER_RUN = 8;
export const ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE = 5;

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

// ---------------------------------------------------------------------------
// What a write costs at the door
// ---------------------------------------------------------------------------

/**
 * How many writes one signing agent may make in a UTC day.
 *
 * Whitepaper Section 5 lets anyone submit with a bare agent key and Section 9
 * prices spam through the paid loop, and both stay true: a key costs nothing to
 * mint, so the free write path needs a ceiling of its own or one process can
 * mint a key per request and spend the log's fetches, its archive and its rows
 * without ever paying for any of it. A day is the same window every read cap is
 * measured over, counted in the same table under its own scope prefix.
 *
 * A placeholder until the paper publishes the number: high enough that no real
 * validator, reconfirmer or scorer meets it in a day's work, low enough that a
 * single key cannot walk the archive up by itself.
 */
export const WRITES_PER_AGENT_PER_DAY = 100;

/**
 * The same cap for an agent of a probation operator, and for a bare key
 * (decision D-131 item 2).
 *
 * D-130: a probation operator "submits at a probationary write cap". The number
 * is a tenth of the established one — enough to file a day's honest work while
 * the operator earns its way to the trusted pool, and small enough that a key
 * factory buys almost nothing by minting operators instead of keys. A bare key
 * is charged here too: it is nobody's operator, so it is nobody's established
 * one either.
 */
export const WRITES_PER_AGENT_PER_DAY_PROBATION = 10;

/**
 * And for an agent of a senior operator (decision D-131 item 2).
 *
 * D-130: senior standing carries "a higher write cap". Three times the
 * established one, which is `WRITES_PER_CLIENT_PER_DAY` — so the ceiling a
 * senior operator actually meets is the client bucket's, and the agent bucket
 * stops being the thing that holds back the operators the record trusts most.
 */
export const WRITES_PER_AGENT_PER_DAY_SENIOR = 300;

// ---------------------------------------------------------------------------
// The vote (decision D-130 item 4)
// ---------------------------------------------------------------------------

/**
 * How long a question stays open, in days (decision D-131 item 2).
 *
 * D-130 item 4: senior operators vote, one operator one vote and one vote per
 * disclosed perimeter, and "the tally is advisory to the maintainer until the
 * record's hosting decentralizes". A week is long enough that an operator that
 * validates on weekdays sees every question, and short enough that a number
 * nobody defends is not left open for a month. Not a whitepaper number: the
 * maintainer's published policy, and the first question put to the vote is
 * whether it and the five beside it are right.
 *
 * The window is end-exclusive (`voteWindow`): a vote cast at the closing
 * instant is a vote cast after the window, and a vote is refused `vote_closed`.
 */
export const VOTE_WINDOW_DAYS = 7;

/**
 * How many questions may be open at once, and it is one.
 *
 * A vote is advisory and its whole value is that the answer is legible: two
 * questions at once share a window, a quorum and a reader's attention, and the
 * second one is answered by whoever is still reading. One question, answered,
 * then the next.
 */
export const VOTE_QUESTIONS_OPEN_MAX = 1;

/**
 * One question put to the senior operators.
 *
 * `id` is the date it opened and a slug, which is what a vote event names and
 * what a tally is keyed by; it never changes, because the events that carry it
 * are sealed. `about` names the POLICY keys the question is about, so a reader
 * can see the numbers under discussion beside the question rather than in a
 * paragraph somewhere else — every string in it is a key of POLICY, which
 * test/policy.test.ts holds.
 *
 * `options` is the ballot and the whole of it: a vote carries one of these
 * strings and nothing else, so a tally is a count and never an interpretation.
 */
export interface VoteQuestion {
  readonly id: string;
  /** The UTC date the window opens on, end-exclusive at + VOTE_WINDOW_DAYS. */
  readonly opened_at: string;
  readonly text: string;
  readonly options: readonly string[];
  /** The POLICY keys this question is about. */
  readonly about: readonly string[];
}

/**
 * Every question, in the order they were opened.
 *
 * The first is the one D-131 item 2 opens with this milestone: the six numbers
 * the tiers and the vote itself are built out of. Composed from the constants
 * rather than from literals — a number that moved and a sentence that did not
 * would be a question about a policy nobody is running.
 */
export const VOTE_QUESTIONS: readonly VoteQuestion[] = Object.freeze([
  Object.freeze({
    id: "2026-09-17-tier-numbers",
    opened_at: "2026-09-17",
    text:
      `Are the six numbers right: the probation write cap ${WRITES_PER_AGENT_PER_DAY_PROBATION}, ` +
      `the senior bar ${STANDING_SENIOR}, early access ${DOMAIN_EARLY_ACCESS_DAYS} days, ` +
      `the senior write cap ${WRITES_PER_AGENT_PER_DAY_SENIOR}, ` +
      `${VOTE_QUESTIONS_OPEN_MAX === 1 ? "one question" : `${VOTE_QUESTIONS_OPEN_MAX} questions`} per vote, ` +
      `a ${VOTE_WINDOW_DAYS === 7 ? "seven" : String(VOTE_WINDOW_DAYS)}-day window?`,
    options: Object.freeze(["keep", "revisit"] as const),
    about: Object.freeze([
      "WRITES_PER_AGENT_PER_DAY_PROBATION",
      "STANDING_SENIOR",
      "DOMAIN_EARLY_ACCESS_DAYS",
      "WRITES_PER_AGENT_PER_DAY_SENIOR",
      "VOTE_QUESTIONS_OPEN_MAX",
      "VOTE_WINDOW_DAYS",
    ] as const),
  }),
]);

/** How many milliseconds a day is. Not a policy number: it is what a day is. */
const MILLISECONDS_IN_A_DAY = 86_400_000;

/**
 * When a question opens and when it closes, both as ISO 8601 instants.
 *
 * The window opens at midnight UTC on `opened_at` and closes exactly
 * `VOTE_WINDOW_DAYS` later, end-exclusive: a vote at `closes` is late. One
 * function, because the door that refuses a late vote and the page that prints
 * the window must not be able to disagree about which day it is.
 */
export function voteWindow(question: VoteQuestion): {
  readonly opens: string;
  readonly closes: string;
} {
  const opens = `${question.opened_at}T00:00:00.000Z`;
  const closes = new Date(
    Date.parse(opens) + VOTE_WINDOW_DAYS * MILLISECONDS_IN_A_DAY,
  ).toISOString();
  return { opens, closes };
}

/** One question by id, or null when no question carries it. */
export function voteQuestion(id: unknown): VoteQuestion | null {
  if (typeof id !== "string") return null;
  return VOTE_QUESTIONS.find((question) => question.id === id) ?? null;
}

/**
 * How many writes one client address may make in a UTC day, across every agent
 * it signs as.
 *
 * The per-agent cap alone buys nothing against a caller that mints a fresh key
 * per request, which is exactly what a bare key makes free. This is the bucket
 * that counts the caller rather than the name they signed under, keyed by the
 * same hashed client scope the read path already counts a keyless reader under
 * (src/keys.ts) — hashed, because a counter that stored addresses would be a
 * record of who wrote what.
 *
 * Higher than the per-agent cap, because one address legitimately carries an
 * operator's several agents. A placeholder, like the number above it.
 */
export const WRITES_PER_CLIENT_PER_DAY = 300;

/**
 * The largest request body any door will read, in bytes.
 *
 * Every write door reads its body before it can verify anything about it — the
 * signature is over the canonical body — so the body is the one thing a caller
 * can make arbitrarily expensive before proving anything at all. The cap is
 * checked against `Content-Length` before a byte is read and enforced again
 * against what actually arrives, so a body that declares nothing is refused at
 * the cap plus one byte rather than buffered whole.
 *
 * A placeholder. 256 KiB is far above the largest real submission — a signed
 * core with a frozen transcript — and far below the point where parsing costs
 * anything worth attacking with.
 */
export const REQUEST_MAX_BODY_BYTES = 262144;

/**
 * The longest a free-text core field may be, in characters.
 *
 * `claim`, `before`, `after` and `citation` are signed, sealed, derived over and
 * served forever, and nothing in the schema bounds them: a one-megabyte claim is
 * a permanent row, a permanent export line and a permanent page. The ceiling is
 * a door rule and not a schema change, so every entry already in the log stays
 * valid and readable exactly as it is.
 *
 * A placeholder. Long enough for a paragraph of what changed and a URL, short
 * enough that a claim is a claim.
 */
export const CORE_TEXT_MAX_CHARS = 4000;

/**
 * The largest `evidence` or `observation` a core may carry, as the byte length
 * of its RFC 8785 canonical form.
 *
 * Measured over the canonical bytes because those are the bytes that are hashed,
 * archived and re-canonicalized by every verifier: bounding what is hashed is
 * bounding the work, where bounding a key count or a depth would not be.
 *
 * A placeholder. 64 KiB holds a full transcript artifact with room to spare.
 */
export const EVIDENCE_MAX_BYTES = 65536;

/**
 * How many pre-0019 rows one sweep run gives a `duplicate_key`.
 *
 * Migration 0019 materialised the duplicate rule as a column and an index, but
 * the key is Unicode normalization and whitespace folding over arbitrary text,
 * which SQL cannot run: the backfill is code, and the sweep is where code runs
 * on a clock. So the step recomputes the key from each row's own entry_json
 * through the same function the door uses, this many rows at a time, and the
 * next run resumes with whatever is left — the same bound, for the same reason,
 * as LEDGER_ENTRIES_PER_RUN and ALERT_EVENTS_PER_RUN.
 *
 * A row written since 0019 carries its key by construction, so on a log with
 * nothing left to fill the step is one bounded SELECT that comes back empty and
 * writes nothing. The number only has to be large enough to finish a migrated
 * log in a reasonable number of runs and small enough to leave a run's other
 * steps their subrequests.
 */
export const DUPLICATE_BACKFILL_PER_RUN = 200;

/** Every policy number, collected and frozen. */
export const POLICY = Object.freeze({
  TRUSTED_POOL_SWITCH,
  APPROVALS_TO_VERIFY_SMALL_POOL,
  APPROVALS_TO_VERIFY_LARGE_POOL,
  REJECTIONS_TO_REJECT,
  VERIFICATION_MIN_OUTSIDE_OPERATORS,
  // Two paths to being a validator, one registry (D-138).
  OPERATOR_KINDS,
  BINDING_KINDS,
  COUNTING_BINDING_KINDS,
  COMMUNITY_MIN_ACCOUNTS,
  COMMUNITY_MIN_COMMUNITIES,
  VERIFICATION_CLASSES,
  CONFIRMATION_ATTESTATION_TOKEN_PREFIX,
  ASSIGNMENT_WINDOW_HOURS,
  DRAW_DRAFT_MAX_AGE_DAYS,
  REPRODUCTION_RUNS,
  REPRODUCTION_HOLDS,
  DOMAINS,
  HOLDBACK_DAYS,
  SEAL_INTERVAL_MINUTES,
  SWEEP_INTERVAL_MINUTES,
  STATUS_ATTENTION_AFTER_INTERVALS,
  STATUS_FAILING_AFTER_MINUTES,
  WITNESSES_REQUIRED,
  SEAL_MAX_EVENTS,
  SWEEP_BATCH_STATEMENTS,
  LEDGER_ENTRIES_PER_RUN,
  WITNESS_FILE_TAIL_BYTES,
  REGISTRY,
  WITNESS_PIN,
  // Where a public confirmation may be said, and in what words (D-136).
  CONFIRMATION_VENUES,
  ACCOUNT_STATEMENT_VENUES,
  CONFIRMATION_FORM_PREFIX,
  CONFIRMATION_REASON_MAX_CHARS,
  CONFIRMATIONS_PER_RUN,
  CONFIRMATION_COMMENTS_PER_THREAD,
  BOARD_READ_MAX_BYTES,
  // What the batch post asks for, and how much of the listing it reads (D-136
  // item 6).
  BATCH_ASK_LIMIT,
  BATCH_READ_PAGES_MAX,
  ANCHOR_CALENDARS,
  FAILURE_REPORT_THRESHOLD,
  DISPUTE_STAKE_STANDING,
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
  // Standing is an asset, and what each tier of it buys (D-130, D-131 item 2).
  TIERS,
  STANDING_SENIOR,
  DOMAIN_EARLY_ACCESS_DAYS,
  // The vote (D-130 item 4, D-131 item 2).
  VOTE_WINDOW_DAYS,
  VOTE_QUESTIONS_OPEN_MAX,
  VOTE_QUESTIONS,
  STANDING_DECAY_PAUSED,
  RELEASE_WINDOW_DAYS,
  RATE_TIERS,
  FREE_TIER,
  FREE_READS_PER_DAY_GLOBAL,
  OPERATOR_READS_PER_DAY,
  ALERT_ENDPOINTS_PER_KEY,
  ALERT_TIMEOUT_MS,
  ALERT_RETRY_MINUTES,
  ALERT_EVENTS_PER_RUN,
  ALERT_DELIVERIES_PER_RUN,
  ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE,
  ALERT_KINDS,
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
  SITEMAP_MAX_ENTRIES,
  PAGE_CACHE_SECONDS,
  PAGE_CACHE_STALE_SECONDS,
  BEACON,
  // What a write costs at the door.
  WRITES_PER_AGENT_PER_DAY,
  WRITES_PER_AGENT_PER_DAY_PROBATION,
  WRITES_PER_AGENT_PER_DAY_SENIOR,
  WRITES_PER_CLIENT_PER_DAY,
  REQUEST_MAX_BODY_BYTES,
  CORE_TEXT_MAX_CHARS,
  EVIDENCE_MAX_BYTES,
  // What one sweep run backfills.
  DUPLICATE_BACKFILL_PER_RUN,
});

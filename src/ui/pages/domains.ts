/**
 * Domains: what a domain is, and the tables the registered ones publish.
 *
 * Whitepaper Section 3, The log: the mechanism does not care about the subject
 * area. A fact is a claim, a citation, a snapshot hash and a set of signatures,
 * and none of those is AI-shaped. What is domain-shaped is the tables — which
 * categories exist, how long each stays fresh, which carry a transcript, who is
 * too close to judge (Section 10's neutral exclusion rule), and how a subject is
 * named — so this page is those tables, read out of the one module that holds
 * them.
 *
 * Which is the whole discipline here: not one number, host, category or
 * attestation sentence on this page is written down. Every one of them is read
 * from src/policy.ts at render time, so a decision that adds a domain, moves a
 * window or publishes another excluded party moves this page with it and cannot
 * leave it quietly describing a rule the log no longer runs. The prose form of
 * the same content is schema/nomankind-domain-registry-v1.md.
 *
 * What the policy module does not hold is the copy: what a domain records, who
 * reads it, what it is for. That is editorial rather than a rule, so it lives in
 * `DOMAIN_COPY` below, keyed by slug, and a test pins its key set against
 * `DOMAIN_SLUGS` — a later registered domain has to bring its own sentences or
 * the suite says so.
 *
 * Pure, like every page in this directory: the two live counters per domain
 * arrived gathered (src/worker/pages.ts) and nothing here reads a database, a
 * clock or the network.
 */

import {
  DOMAIN_SLUGS,
  SCHEMA_VERSION,
  attestationFor,
  domainPolicy,
  excludedPartyDomains,
  stalenessWindowDays,
  type DomainPolicy,
} from "../../policy.js";
import { badge, html, layout, raw, type Safe } from "../html.js";
import type { DomainCounts, DomainsData, PageContext } from "../types.js";

/**
 * The version of the domain registry document this page is a reading of.
 *
 * Not a policy number: policy is what the record runs on, and this is the
 * version of the published document whose tables the policy module holds
 * (schema/nomankind-domain-registry-v1.md). Named once here, beside the page
 * that shows it, exactly as the how-it-works page names the paper's version.
 */
const REGISTRY_VERSION = "v1";

/** How many excluded parties are named on the page before the policy page takes over. */
const EXCLUDED_SHOWN = 7;

/**
 * What a domain is for, in words: the half of a domain that is editorial rather
 * than a rule.
 *
 * Everything a domain *enforces* is in src/policy.ts and is read from there. The
 * fields below are the things a rule cannot say — what the domain records, why
 * anybody would read it, who is expected to, and an example subject — and they
 * are here rather than in policy because a sentence nobody validates against is
 * not policy and must not be able to pass for it.
 *
 * Keyed by slug, and the key set is pinned against `DOMAIN_SLUGS` by
 * test/ui-pages-docs.test.ts: a domain registered by a later decision arrives on
 * this page with its own copy or the suite refuses the drift.
 */
export interface DomainCopy {
  /** One line for the strip at the top of the page. */
  readonly short_line: string;
  readonly what: string;
  readonly use_case: string;
  readonly who_reads: string;
  readonly who_validates: string;
  /** A subject written the domain's own way, for the example read call. */
  readonly subject_example: string;
  /** One sentence about what the domain's non-transcript categories carry. */
  readonly transcript_note: string;
}

export const DOMAIN_COPY: Readonly<Record<string, DomainCopy>> = Object.freeze({
  "ai-ecosystem": Object.freeze({
    short_line: "What models cost and do.",
    what: "What models and AI products cost and do. A release, a deprecation, a price, a limit, an outage, or a measured behavior of a model, stated by the provider's own page or observed under a receipt and a frozen transcript.",
    use_case:
      "An agent that calls other models needs the price, the limit, and the deprecation state that hold today, without trusting one vendor's changelog and without re-reading the web. A continual learner syncs the delta, weights a measured behavior above a quoted one, and unlearns a fact when a dispute overturns it.",
    who_reads:
      "Agent frameworks and model gateways that route across providers; evaluation and observability tooling; teams that keep a model's knowledge of the ecosystem current; anyone who needs a citable, dated answer to what a provider said and whether it held.",
    who_validates:
      "Operators outside every model provider, attested in this domain. The genesis call names operators for this domain.",
    subject_example: "openai/gpt-5",
    transcript_note:
      "every other category carries its measurement in the observation.",
  }),
  "ai-governance": Object.freeze({
    short_line: "What states and intergovernmental bodies require.",
    what: "Instruments issued by states and intergovernmental bodies, binding or soft law: the EU AI Act, the Council of Europe Framework Convention on AI, state laws, executive orders, ISO 42001, the NIST AI Risk Management Framework, the OECD Principles, UNESCO's Recommendation. What is in force, what was amended or repealed, what guidance was issued, what was enforced.",
    use_case:
      "A system that must act under the rules of a jurisdiction needs to know which instrument is in force today and what changed since it last looked, cited to the issuing body's own gazette rather than to commentary about it. The record answers what the law says with the text the state published, dated and sealed.",
    who_reads:
      "Compliance and legal tooling; policy researchers and trackers; agents deployed across jurisdictions; the bodies that issue the instruments, reading how their own text is being cited.",
    who_validates:
      "Operators attested in this domain. The issuing body of an instrument may not validate an entry about it, and model providers are excluded here as everywhere.",
    subject_example: "eu/ai-act",
    transcript_note:
      "no category carries a transcript; every entry is confirmed against the cited instrument.",
  }),
  "ai-safety": Object.freeze({
    short_line: "What non-state parties committed to, and what their systems do.",
    what: "What non-state parties committed to about harm to people, and what their deployed systems and guardrail products actually do. Lab constitutions, scaling and preparedness policies, usage policies, industry safety commitments, civil-society principles, guardrail products; and the measured conduct beside them: refusals, filters, safety evaluations, incidents.",
    use_case:
      "Hold a commitment against conduct. A published policy is a stated fact; a refusal or a filter behavior is an observed one with a transcript; both sit on the same subject, so the gap between what a party said and what its system did is a query over the log rather than an argument.",
    who_reads:
      "Safety researchers and red teams; civil-society monitors; buyers comparing guardrail products; journalists; the parties themselves, whose commitments are on the record they cannot edit.",
    who_validates:
      "Operators attested in this domain. Model providers, guardrail vendors, and any party they fund are excluded from validating here.",
    subject_example: "anthropic/usage-policy",
    transcript_note:
      "a transcript holding a working jailbreak is archived with its payload redacted and published after the disclosure window, its hash intact.",
  }),
});

/** `1 day` or `90 days`: a count and the word for it. */
function plural(count: number, singular: string, many?: string): string {
  const other = many ?? `${singular}s`;
  return count === 1 ? `${count} ${singular}` : `${count} ${other}`;
}

/** The index of a domain in the registry, shown as the strip shows it: 01, 02. */
function ordinal(index: number): string {
  return String(index + 1).padStart(2, "0");
}

/** One key/value line of a panel: the term, and what the tables say. */
function row(term: string, value: Safe): Safe {
  return html`<dt>${term}</dt>
        <dd>${value}</dd>`;
}

/** The badge a domain wears: recruited once the log holds a trusted operator in it. */
function domainBadge(trustedOperators: number): Safe {
  return trustedOperators > 0
    ? badge("s-verified", "recruited")
    : badge("s-draft", "registered");
}

/**
 * The freshness line, computed from the domain's own window table.
 *
 * Whitepaper Section 7, Freshness and decay: a volatile category carries a
 * window from the last-confirmed date and an event category carries none,
 * because once it happened it stays true. So the two halves are read apart here
 * rather than written down — the categories that carry a window with the days
 * the table gives them, and the rest named as what they are.
 */
function freshness(slug: string): string {
  const categories = domainPolicy(slug).categories;
  const timed: string[] = [];
  const untimed: string[] = [];
  for (const category of categories) {
    const days = stalenessWindowDays(slug, category);
    if (days === null) untimed.push(category);
    else timed.push(`${category} ${plural(days, "day")}`);
  }
  const first =
    timed.length === 0
      ? "No category carries a window."
      : `${timed.join(" · ")}.`;
  if (untimed.length === 0) return first;
  return `${first} The rest never go stale: ${untimed.join(", ")}.`;
}

/** Somebody a domain's operators may not be, counted and then named as far as the page goes. */
function excluded(slug: string): Safe {
  const hosts = excludedPartyDomains(slug);
  const shown = hosts.slice(0, EXCLUDED_SHOWN).join(", ");
  const rest = hosts.length - Math.min(hosts.length, EXCLUDED_SHOWN);
  return rest > 0
    ? html`${plural(hosts.length, "party", "parties")}: ${shown}, and
        <a href="/policy">the rest on the policy page</a>.`
    : html`${plural(hosts.length, "party", "parties")}: ${shown}. The table is
        on <a href="/policy">the policy page</a>.`;
}

/**
 * The delayed-disclosure rule, when the domain publishes one (decision D-096).
 *
 * Nothing at all when it does not, which is most domains: a row reading "none"
 * would look like a rule that had been considered and set to nothing, and what
 * is true is that the domain has no such rule to publish. The categories and
 * the window are the policy object's own — the page names neither list nor
 * number of its own — so a window the maintainer moves moves here with it.
 */
function disclosureRow(policy: DomainPolicy): Safe {
  const rule = policy.disclosure;
  if (rule === undefined) return raw("");
  return row(
    "Delayed disclosure",
    html`<span class="badges"
        >${rule.categories.map((each) => badge("", each))}</span
      >
      A transcript in one of those may be submitted with its payload replaced by
      a hash. The payload itself is archived at submission and published
      ${plural(rule.window_days, "day")} after it, so the evidence becomes
      public on a stated clock and the transcript's own hash never changes.`,
  );
}

/**
 * The categories whose subject carries a version, when the domain has them.
 *
 * The same discipline as above: absent means the domain publishes no such rule,
 * and the categories are read from the table rather than named here.
 */
function versionStalenessRow(policy: DomainPolicy): Safe {
  const rule = policy.version_staleness;
  if (rule === undefined) return raw("");
  return row(
    "Staleness on a version change",
    html`<span class="badges"
        >${rule.categories.map((each) => badge("", each))}</span
      >
      A subject in one of those names the version it was observed against, and
      the entry goes stale the moment an entry about another version of the same
      model verifies: what was measured was measured on a version that is gone,
      and a reconfirmation cannot bring it back.`,
  );
}

/** One domain's panel: its tables, its live counters, and the way in. */
function domainPanel(
  slug: string,
  index: number,
  copy: DomainCopy,
  counts: DomainCounts,
): Safe {
  const policy = domainPolicy(slug);
  const attestation = attestationFor(slug);
  const sources = policy.sources;
  const transcripts =
    policy.transcript_categories.length === 0
      ? "none"
      : policy.transcript_categories.join(", ");
  const category = policy.categories[0] ?? "";

  return html`<section class="panel" id="${slug}">
        <h2 class="panel-title">
          <span class="stage-num">${ordinal(index)}</span>${policy.name}
          <span class="mono dim">${slug}</span>
          ${domainBadge(counts.trustedOperators)}
        </h2>
        <dl class="dl">
          ${row("What it records", html`${copy.what}`)}
          ${row("Use case", html`${copy.use_case}`)}
          ${row("Who reads it", html`${copy.who_reads}`)}
          ${row("Who validates it", html`${copy.who_validates}`)}
          ${row(
            "Subject",
            html`${policy.subject_convention}, as
              <span class="mono">${copy.subject_example}</span>.`,
          )}
          ${row(
            "Categories",
            html`<span class="badges"
              >${policy.categories.map((each) => badge("", each))}</span
            >`,
          )}
          ${row(
            "Transcripts",
            html`${transcripts} — ${copy.transcript_note}`,
          )}
          ${row("Freshness", html`${freshness(slug)}`)}
          ${row("Excluded parties", excluded(slug))}
          ${row(
            "Attestation",
            html`“${attestation.text}”
              <span class="mono dim">${attestation.version}</span>`,
          )}
          ${row(
            "Sources",
            html`Official source required:
              <span class="badges"
                >${sources.official_required.map((each) => badge("", each))}</span
              >
              Every other category may cite any host, and the citation is
              labeled official, recognized, or other.`,
          )}
          ${disclosureRow(policy)}${versionStalenessRow(policy)}
          ${row(
            "In this log",
            html`<a href="/entries?domain=${slug}"
                >${plural(counts.entries, "entry", "entries")}</a
              >
              ·
              <a href="/operators"
                >${plural(counts.trustedOperators, "trusted operator")}</a
              >`,
          )}
        </dl>
        <div class="panel-body">
          <div class="actions">
            <a class="btn btn-accent" href="/entries?domain=${slug}"
              >Browse entries</a
            >
            <a class="btn" href="/policy">Policy tables</a>
            <a class="btn" href="/genesis">Join this domain</a>
          </div>
          <pre class="block">GET /read?domain=${slug}&amp;subject=${copy.subject_example}&amp;category=${category}</pre>
        </div>
      </section>`;
}

/** One cell of the strip across the top, anchored at its own panel. */
function strip(
  slug: string,
  index: number,
  copy: DomainCopy,
  trustedOperators: number,
): Safe {
  return html`<a class="step" href="#${slug}"
        ><span class="step-n">${ordinal(index)} · ${slug}</span
        ><span class="step-t">${domainPolicy(slug).name}</span>
        <span class="note">${copy.short_line}</span>
        <span class="badges">${domainBadge(trustedOperators)}</span></a
      >`;
}

/**
 * The reading for a domain the gather did not count.
 *
 * Zero and not a blank, and it is the honest fallback here rather than a guess:
 * the route counts every registered slug, so an absent reading means a domain
 * registered after this render was gathered — which has no entries and no
 * trusted operator in this log yet, which is what zero says.
 */
const NO_COUNTS: DomainCounts = Object.freeze({
  entries: 0,
  trustedOperators: 0,
});

/** One registered domain as the page walks it: the slug, its place, its copy, its counts. */
interface Registered {
  readonly slug: string;
  readonly index: number;
  readonly copy: DomainCopy;
  readonly counts: DomainCounts;
}

export function renderDomains(ctx: PageContext, data: DomainsData): string {
  // A registered domain with no copy is not rendered rather than rendered
  // empty: the test that pins DOMAIN_COPY against DOMAIN_SLUGS is what catches
  // it, and a panel of blanks would hide the omission behind a heading.
  const registered: Registered[] = [];
  DOMAIN_SLUGS.forEach((slug, index) => {
    const copy = DOMAIN_COPY[slug];
    if (copy === undefined) return;
    registered.push({
      slug,
      index,
      copy,
      counts: data.counts[slug] ?? NO_COUNTS,
    });
  });

  return layout(ctx, {
    title: "Domains",
    description:
      "A domain is a subject area the log records: the same mechanism in every one, and its own tables for categories, freshness, transcripts, excluded parties and subjects.",
    body: html`
      <div class="page-head">
        <h1>Domains</h1>
        <span class="note"
          >registry ${REGISTRY_VERSION} · schema ${SCHEMA_VERSION} ·
          ${DOMAIN_SLUGS.length} registered</span
        >
      </div>
      <p class="lede">
        A domain is a subject area the log records. The mechanism is the same in
        every one: a claim, a citation, a snapshot hash, and the signatures of
        operators no interested party controls. What a domain owns is the
        tables: which categories exist, how long each stays fresh, which carry a
        transcript, who is too close to judge, and how a subject is named. Every
        entry names its domain in its signed core, so a fact can never be moved
        from one domain to another, by anyone.
      </p>

      <div class="counters">
        ${registered.map((each) =>
          strip(each.slug, each.index, each.copy, each.counts.trustedOperators),
        )}
      </div>

      <div class="stack">
        ${registered.map((each) =>
          domainPanel(each.slug, each.index, each.copy, each.counts),
        )}
        <section class="panel">
          <h2 class="panel-title">Adding a domain</h2>
          <div class="panel-body">
            <p class="prose">
              A new domain is a published decision, not a code change: its
              tables are written into the registry first, its slug is added to
              the schema, and the policy module is extended to match, pinned by
              a test so the two never drift. Existing entries are untouched;
              their domain is in their signed core. Operators join a later
              domain by signing that domain's attestation, a public event in the
              log.
            </p>
          </div>
        </section>
      </div>
    `,
  });
}

/**
 * Every published number, in one place, read straight from src/policy.ts.
 *
 * The page holds no number of its own. Every value below is interpolated from
 * the `policy` argument — the frozen POLICY object the kernel and `GET /policy`
 * both read — so a number that moved by decision moves here in the same commit
 * and there is nowhere for the page to disagree with the code. Section 9: every
 * published amount is policy, and policy moves only by a recorded decision.
 *
 * The grouped tables are for a reader; the "all keys" block at the end is for
 * completeness. It is generated from `Object.keys(policy)`, so a constant added
 * to POLICY later appears on this page whether or not anyone remembered to give
 * it a row, and the test holds that promise.
 */

// The two functions of the policy module the page reads (decision D-138). Every
// other value on this page is interpolated from the frozen POLICY object; these
// two are readings of it — the cap is a function of how many communities count,
// and which communities count is a reading of the venue table — so they are
// called here rather than having their answers retyped as numbers.
import {
  communityCapPerEntry,
  countingCommunities,
  DOMAIN_EARLY_ACCESS_DAYS,
  WRITES_PER_AGENT_PER_DAY,
  WRITES_PER_AGENT_PER_DAY_PROBATION,
  WRITES_PER_AGENT_PER_DAY_SENIOR,
  type DomainPolicy,
  type POLICY,
  type Tier,
} from "../../policy.js";
import type { Safe } from "../html.js";
import { html, layout } from "../html.js";
import type { PageContext } from "../types.js";

/** One published number: the constant's own name, its value, what it fixes. */
interface Row {
  readonly name: string;
  readonly value: string;
  readonly means: string;
}

function tableRows(items: readonly Row[]): Safe[] {
  return items.map(
    (row) => html`<tr>
            <td class="mono">${row.name}</td>
            <td class="mono">${row.value}</td>
            <td>${row.means}</td>
          </tr>`,
  );
}

/** One group of numbers, as a panel holding a three-column table. */
function group(title: string, items: readonly Row[]): Safe {
  return html`<section class="panel">
        <h2 class="panel-title">${title}</h2>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>name</th>
                <th>value</th>
                <th>what it fixes</th>
              </tr>
            </thead>
            <tbody>
              ${tableRows(items)}
            </tbody>
          </table>
        </div>
      </section>`;
}

/**
 * What one tier allows, in words, from the policy module (decision D-130).
 *
 * Published here because this is the page that publishes policy, and exported
 * because the operator page prints the same sentence beside the tier `tierOf`
 * answered for it: two pages, one sentence, so a cap that moves by a later
 * decision moves in both in the same commit. Every number in it is
 * interpolated; this function holds none.
 *
 * Standing gates participation and nothing else. None of these sentences says
 * anything about whether an entry is true: a senior operator's approval counts
 * for exactly what a probationary one's counts for, and the consensus rule does
 * not read a tier.
 */
export function tierAllows(tier: Tier): string {
  switch (tier) {
    case "probation":
      return `Volunteer validations, ${WRITES_PER_AGENT_PER_DAY_PROBATION} submits a day per agent, not in the draw, and no disputes.`;
    case "senior":
      return `${WRITES_PER_AGENT_PER_DAY_SENIOR} submits a day per agent, early access to a new domain for ${DOMAIN_EARLY_ACCESS_DAYS} days, and the vote.`;
    default:
      return `${WRITES_PER_AGENT_PER_DAY} submits a day per agent, the validator draw, disputes, and domain joins.`;
  }
}

/** One row of the contribution table: who is asking, and what they are served. */
interface ContributionRow {
  readonly who: string;
  readonly reads: string;
  readonly writes: string;
}

/**
 * Contribution (decision D-130): what standing buys, from keyless to trusted.
 *
 * The caps table used to be framed as a ladder of access and it is not one: no
 * read is priced (D-127), so the only thing a row here differs by is how much
 * of the log's day it may spend and how much it may write. The rows are people
 * — a stranger, a key, an operator at each tier — because that is the question
 * a reader actually has, and every cell is interpolated from the frozen policy
 * object.
 *
 * The free key's tier is read the way the free key door reads it: the first
 * tier in RATE_TIERS that carries a key, so the slug this table prints is the
 * slug a key is actually issued at.
 */
function contributionRows(policy: typeof POLICY): readonly ContributionRow[] {
  const free = policy.RATE_TIERS[policy.FREE_TIER];
  const keyed = Object.entries(policy.RATE_TIERS).find(
    ([, tier]) => tier.key,
  );
  const keylessReads =
    free === undefined
      ? "—"
      : `${free.reads_per_day} a day per client, under ${policy.FREE_READS_PER_DAY_GLOBAL} a day across every client`;
  const keyedReads =
    keyed === undefined
      ? "—"
      : `${keyed[1].reads_per_day} a day, counted per key (${keyed[0]})`;
  const operatorReads = `${policy.OPERATOR_READS_PER_DAY} a day on signed reads, counted per operator`;
  const clientWrites = `, and ${policy.WRITES_PER_CLIENT_PER_DAY} a day per client address across every agent it signs as`;
  return [
    {
      who: "keyless",
      reads: keylessReads,
      writes: `${WRITES_PER_AGENT_PER_DAY_PROBATION} a day per agent${clientWrites}. A bare key has no operator and so no standing: it may submit and it may not dispute.`,
    },
    {
      who: "free key",
      reads: keyedReads,
      writes: `The same as keyless: a key is a read identity and buys no write. ${WRITES_PER_AGENT_PER_DAY_PROBATION} a day per agent${clientWrites}.`,
    },
    {
      who: "registered operator · probation",
      reads: operatorReads,
      writes: tierAllows("probation"),
    },
    {
      who: "registered operator · established",
      reads: operatorReads,
      writes: tierAllows("established"),
    },
    {
      who: "registered operator · senior",
      reads: operatorReads,
      writes: tierAllows("senior"),
    },
    {
      who: "trusted operator",
      reads: operatorReads,
      writes: `Its own tier's writes, and drawn from the trusted pool: entry at ${policy.STANDING_TRUSTED_ENTRY} standing, kept at or above ${policy.STANDING_TRUSTED_STAY}.`,
    },
  ];
}

/** The contribution table itself. */
function contributionTable(policy: typeof POLICY): Safe {
  return html`<section class="panel">
        <h2 class="panel-title">Contribution</h2>
        <p class="note">
          The one thing standing buys is rate — how much of the log's day a
          caller may spend reading and writing — and it never buys truth: no cap
          and no tier on this table is read by the consensus rule, and an entry
          is verified by the decisions under it and by nothing else.
        </p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>who</th>
                <th>reads</th>
                <th>writes</th>
              </tr>
            </thead>
            <tbody>
              ${contributionRows(policy).map(
                (row) => html`<tr>
                    <td class="mono">${row.who}</td>
                    <td>${row.reads}</td>
                    <td>${row.writes}</td>
                  </tr>`,
              )}
            </tbody>
          </table>
        </div>
      </section>`;
}

/** A list-valued constant, one item per line, in order. */
function listRows(name: string, values: readonly string[]): Safe[] {
  return values.map(
    (value, index) => html`<tr>
            <td class="mono">${name}[${index}]</td>
            <td class="mono">${value}</td>
          </tr>`,
  );
}

/**
 * One registered domain's published tables (decision D-071).
 *
 * Everything that used to be a category-keyed global — the staleness windows,
 * the transcript categories, the excluded-party list — is a field of a domain
 * now, so it is published per domain and named by the path it actually lives
 * at: `DOMAINS.<slug>.staleness_window_days.<category>` and not a global a
 * reader would have to guess applies everywhere. Whitepaper Section 3: the
 * mechanism does not care about the domain, and what is domain-shaped is the
 * tables. Every value is read off the frozen object; the page holds none.
 */
function domainPanel(slug: string, domain: DomainPolicy): Safe {
  const path = `DOMAINS.${slug}`;
  const rows: Row[] = [
    {
      name: `${path}.name`,
      value: domain.name,
      means: "What this domain is called where a domain is named in words.",
    },
    {
      name: `${path}.categories`,
      value: domain.categories.join(", "),
      means:
        "Every category this domain admits. The schema's category enum is the union of every registered domain's categories; which of them a domain admits is enforced from this table, so a category filed in a domain that does not admit it is refused at submission.",
    },
    ...domain.categories.map((category) => {
      const days = domain.staleness_window_days[category];
      return {
        name: `${path}.staleness_window_days.${category}`,
        value: days === null ? "no window (event category)" : `${days} days`,
        means:
          days === null
            ? `An entry in the ${category} category of this domain carries no freshness window: once it happened it stays true, so it never goes stale.`
            : `A ${category} entry in this domain expires ${days} days after its last confirmation, and reads on it are marked stale until a trusted operator reconfirms it.`,
      };
    }),
    {
      name: `${path}.transcript_categories`,
      value: domain.transcript_categories.join(", "),
      means:
        "The categories of this domain whose evidence is a transcript rather than a document, which is what decides the shape a validator's reproduction has to take.",
    },
    {
      name: `${path}.excluded_parties.subject_authority`,
      value: String(domain.excluded_parties.subject_authority),
      means:
        "Whether the entry's own subject excludes an operator as well as the list below does: when true, an operator whose domain is, or is under, an official host of the subject's authority row may not validate, reconfirm or be drawn for that entry. The list is about the domain; this is about the single entry, and it is false where the two already coincide.",
    },
    {
      name: `${path}.excluded_parties.rule`,
      value: domain.excluded_parties.rule,
      means:
        "Section 10, in this domain's own words: no party whose products or conduct the record checks may control, fund, or validate it in that domain. The list below is the cheap first check and never the whole enforcement — the signed attestation is what binds.",
    },
    {
      name: `${path}.attestation.version`,
      value: domain.attestation.version,
      means:
        "The version of the independence attestation an operator signs to join this domain. The sentence itself is published verbatim on the genesis page, because a paraphrase of a signed string is not the signed string.",
    },
    {
      name: `${path}.subject_convention`,
      value: domain.subject_convention,
      means:
        "How a subject is named in this domain, so two entries about the same thing are about the same subject.",
    },
    // The two rules a domain may publish and most do not. A row per field only
    // where the field is there: printing "none" for a domain that has no such
    // rule would publish a decision nobody took.
    ...(domain.disclosure === undefined
      ? []
      : [
          {
            name: `${path}.disclosure.categories`,
            value: domain.disclosure.categories.join(", "),
            means:
              "The categories of this domain whose transcript may be submitted with its request payload replaced by the hash of the original. The transcript's hash is taken over the artifact as submitted, placeholders and all, so the signature covers exactly what was archived.",
          },
          {
            name: `${path}.disclosure.window_days`,
            value: `${domain.disclosure.window_days} days`,
            means:
              "How long after an entry's submitted_at the redacted payload stays private. The payload is archived at submission and served to a signed operator throughout, because a validator has to reproduce the measurement; an unsigned read before the window is refused 403 undisclosed and carries the date it opens.",
          },
        ]),
    ...(domain.version_staleness === undefined
      ? []
      : [
          {
            name: `${path}.version_staleness.categories`,
            value: domain.version_staleness.categories.join(", "),
            means:
              "The categories of this domain whose subject carries a version as its third segment. An entry in one of them goes stale when an entry about another version of the same model verifies, and stays stale: a reconfirmation is refused version_stale, because the version it observed is gone.",
          },
        ]),
  ];
  return html`<section class="panel">
        <h2 class="panel-title">Domains · ${slug}</h2>
        <p class="note">
          One registered domain's published tables. Nothing category-shaped is
          global any more: a window, a transcript rule and an excluded party all
          belong to a domain, and an entry is read under the domain its own
          signed core names.
        </p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>name</th>
                <th>value</th>
                <th>what it fixes</th>
              </tr>
            </thead>
            <tbody>
              ${tableRows(rows)}
            </tbody>
          </table>
        </div>
        <div class="table-wrap">
          <table class="table">
            <tbody>
              ${listRows(
                `${path}.excluded_parties.domains`,
                domain.excluded_parties.domains,
              )}
            </tbody>
          </table>
        </div>
      </section>`;
}

/**
 * One registered domain's source policy (decision D-080).
 *
 * The gap this closes is stated on the page itself, because a table without it
 * reads as trivia: a stated entry verifies when independent operators confirm
 * the source said what the entry says, and nothing in that checks the source is
 * one that should be believed about the subject. So a category whose claim has
 * an authoritative source by nature must cite that source or it is refused at
 * submission, and every other citation is labeled rather than gated.
 *
 * Three tables, all read off the frozen object and none of them retyped here:
 * the categories the gate applies to, one row per authority with the hosts it
 * publishes under, and the recognized list. The judgment the policy does not
 * automate is named in words underneath, because a reader who took the tables
 * for the whole check would be trusting a hostname where the actual promise is
 * that three operators read the page.
 */
function sourcesPanel(slug: string, domain: DomainPolicy): Safe {
  const path = `DOMAINS.${slug}.sources`;
  const sources = domain.sources;
  const authorities = Object.entries(sources.authorities);
  return html`<section class="panel">
        <h2 class="panel-title">Domains · ${slug} · sources</h2>
        <p class="note">
          A stated entry is verified when independent operators confirm the cited
          source said what the entry says. That checks the reading and not the
          reader's standing to say it, so a site made yesterday could otherwise
          carry a pricing claim to verified. The categories below have an
          authoritative source by nature: an entry in one of them must cite the
          subject's own official source or it is refused at submission, with
          <span class="mono">source_not_official</span>, or with
          <span class="mono">unknown_authority</span> when this table holds no row
          for the subject's primary party at all. Every other citation is classified
          and labeled — <span class="mono">official</span>,
          <span class="mono">recognized</span>,
          <span class="mono">other</span> — and never gated.
        </p>
        <p class="note">
          The host rule: the citation must be
          <span class="mono">https</span>, and its lowercased host must equal a
          listed host or be a subdomain of one, so
          <span class="mono">docs.anthropic.com</span> matches
          <span class="mono">anthropic.com</span> and
          <span class="mono">anthropic.com.evil.tld</span> does not. A port or
          userinfo in the URL makes it <span class="mono">other</span>. The
          authority is the subject's primary party: the first path segment,
          lowercased, under this domain's subject convention.
        </p>
        <div class="table-wrap">
          <table class="table">
            <tbody>
              <tr>
                <td class="mono">${path}.official_required</td>
                <td class="mono">${sources.official_required.join(", ")}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>authority</th>
                <th>official hosts</th>
              </tr>
            </thead>
            <tbody>
              ${authorities.map(
                ([authority, row]) => html`<tr>
                  <td class="mono">
                    ${row.fixture === true ? `${authority} (fixture)` : authority}
                  </td>
                  <td class="mono">${row.hosts.join(", ")}</td>
                </tr>`,
              )}
            </tbody>
          </table>
        </div>
        <div class="table-wrap">
          <table class="table">
            <tbody>
              ${listRows(`${path}.recognized_hosts`, sources.recognized_hosts)}
            </tbody>
          </table>
        </div>
        <p class="note">
          A validator's approval asserts that the cited page supports the claim.
          That is the judgment this policy does not automate and does not replace:
          the tables above say which sources may be cited for what, and three
          independent operators still say whether the page cited actually says
          it. An authority absent from the table has no published official source
          here, so its official-required claims are refused until a recorded
          decision adds the row.
        </p>
      </section>`;
}

/**
 * The page.
 *
 * `policy` is the whole frozen object rather than the individual constants: a
 * page handed the object cannot print a number the object does not hold, and
 * the last block can enumerate it.
 */
export function renderPolicy(ctx: PageContext, policy: typeof POLICY): string {
  // Two paths to being a validator, one registry (decision D-138). Every value
  // is the published constant or a reading of it: the counting communities are
  // the venue table filtered by binding kind, and the per-entry cap is the
  // function of how many of them there are, called with that number rather than
  // written out as one.
  const counting = countingCommunities();
  const community: Row[] = [
    {
      name: "OPERATOR_KINDS",
      value: policy.OPERATOR_KINDS.join(", "),
      means:
        "The two kinds of operator one registry holds. A domain operator is a key bound by a TXT record under a DNS name it controls, registered through the registration door with a signed attestation. A community operator is a key bound to an account on an agent community, registered implicitly by its first counted confirmation line carrying the attestation token: no form and no door. Both validate, both earn standing, and an entry says which kinds met its consensus rather than pretending there is one kind.",
    },
    {
      name: "BINDING_KINDS",
      value: policy.BINDING_KINDS.join(", "),
      means:
        "How a community key may be bound to a public identity, an open list. registry: a key-bind in a registry whose log the pinned witnesses countersign. profile: the public key published on the agent's own profile page, captured and sealed exactly as a citation is. platform: a platform's statement about an account.",
    },
    {
      name: "COUNTING_BINDING_KINDS",
      value: policy.COUNTING_BINDING_KINDS.join(", "),
      means:
        "The binding kinds a counted validation may rest on. A platform's statement is shown and never counted, because it is somebody else's assertion rather than something anyone can recheck offline, and a bare key never counts whatever it signs: the point of a binding is that the world can see whose key it is.",
    },
    {
      name: "COMMUNITY_MIN_ACCOUNTS",
      value: String(policy.COMMUNITY_MIN_ACCOUNTS),
      means:
        "The Sybil floor for a consensus met by community operators alone: this many distinct bound accounts. A DNS name and a signed attestation cost more than an account on a board, so a consensus resting on accounts alone is asked for more of them.",
    },
    {
      name: "COMMUNITY_MIN_COMMUNITIES",
      value: String(policy.COMMUNITY_MIN_COMMUNITIES),
      means:
        "And from how many distinct communities, enforced only while more than one community counts. A rule demanding two communities in a world with one would refuse every community consensus there could be, which is a moratorium and not a Sybil rule.",
    },
    {
      name: "countingCommunities()",
      value: counting.length === 0 ? "none" : counting.join(", "),
      means:
        "The venues a community validation may be counted from: the confirmation venues whose binding kind counts. A reading of the venue table and never a second list, so a venue whose binding changes changes this in the same commit.",
    },
    {
      name: `communityCapPerEntry(${counting.length})`,
      value: String(communityCapPerEntry(counting.length)),
      means:
        counting.length <= 1
          ? `How many community validations of one entry may be counted from one community. With one counting community the cap is the whole consensus — there is nowhere else for a validation to come from, and COMMUNITY_MIN_ACCOUNTS above is what carries the weight. Once two communities count it falls to VERIFICATION_MIN_OUTSIDE_OPERATORS minus COMMUNITY_MIN_COMMUNITIES plus one, so that one board can never supply a consensus by itself.`
          : `How many community validations of one entry may be counted from one community. With ${counting.length} counting communities the cap is VERIFICATION_MIN_OUTSIDE_OPERATORS minus COMMUNITY_MIN_COMMUNITIES plus one, so one board can never supply a consensus by itself: the last seat has to come from somewhere else.`,
    },
    {
      name: "VERIFICATION_CLASSES",
      value: policy.VERIFICATION_CLASSES.join(", "),
      means:
        "What an entry discloses about who met its consensus, weakest first: registered when domain operators alone met it, mixed when domain operators took part but community operators were needed to reach it, community otherwise. The order is the order of the min_class filter on the read doors, so min_class=mixed admits mixed and registered. Sealed history and not a rating: the class is derived from the validators counted at the decision seal and is never relabelled by later evidence, which arrives as an additive dated layer instead.",
    },
    {
      name: "CONFIRMATION_ATTESTATION_TOKEN_PREFIX",
      value: `${policy.CONFIRMATION_ATTESTATION_TOKEN_PREFIX}<version>`,
      means:
        "The token that turns a public confirmation into a validation. A confirmation line carrying it is its author's signature over this record's independence attestation at that version, said once, in the line itself — which is how a community operator attests with no form and no registration door. A line without it stays a public confirmation: shown, clearing the bootstrap label, counted toward no status.",
    },
  ];

  const validation: Row[] = [
    {
      name: "TRUSTED_POOL_SWITCH",
      value: `${policy.TRUSTED_POOL_SWITCH} operators`,
      means:
        "The trusted-pool size at which verification switches to three approvals and the random draw. Below it, no draw is made at all.",
    },
    {
      name: "APPROVALS_TO_VERIFY_SMALL_POOL",
      value: String(policy.APPROVALS_TO_VERIFY_SMALL_POOL),
      means:
        "Approvals that verify an entry while the trusted pool is below the switch.",
    },
    {
      name: "APPROVALS_TO_VERIFY_LARGE_POOL",
      value: String(policy.APPROVALS_TO_VERIFY_LARGE_POOL),
      means:
        "Approvals that verify an entry once the pool is at or above the switch, at least one of them from the randomly assigned validator.",
    },
    {
      name: "REJECTIONS_TO_REJECT",
      value: String(policy.REJECTIONS_TO_REJECT),
      means: "Rejections that reject an entry, at either pool size.",
    },
    {
      name: "VERIFICATION_MIN_OUTSIDE_OPERATORS",
      value: String(policy.VERIFICATION_MIN_OUTSIDE_OPERATORS),
      means:
        "Verified operators outside the submitter's own that must exist before anything in the log can reach verified (Section 6).",
    },
    {
      name: "ASSIGNMENT_WINDOW_HOURS",
      value: `${policy.ASSIGNMENT_WINDOW_HOURS} hours`,
      means:
        "How long an assigned validator has to respond. A miss costs standing and the next sweep draws a replacement.",
    },
    {
      name: "DRAW_DRAFT_MAX_AGE_DAYS",
      value: `${policy.DRAW_DRAFT_MAX_AGE_DAYS} days`,
      means:
        "How old a draft may be, counted from its submitted_at to the sweep's own clock, and still be drawn a validator. Past it the draft leaves the draw queue and stops costing every run: it is still a draft, still in the log, still readable, and a volunteer may still validate it — what it stops getting is a draw. The cutoff is on submitted_at, which nothing moves, so a validation does not put an older draft back in the queue.",
    },
    {
      name: "BEACON.endpoint",
      value: policy.BEACON.endpoint,
      means:
        "The public randomness beacon the validator draw reads. The draw is a deterministic function of a beacon round, the entry id, and a published pool snapshot, so anyone can recompute it.",
    },
    {
      name: "BEACON.beacon_id",
      value: policy.BEACON.beacon_id,
      means: "Which chain on that beacon the draw uses.",
    },
    {
      name: "BEACON.chain_hash",
      value: policy.BEACON.chain_hash,
      means:
        "The chain's identifying hash, pinned so an offline reader can recheck a draw years later against the same chain the draw used.",
    },
    {
      name: "BEACON.genesis_time",
      value: String(policy.BEACON.genesis_time),
      means:
        "The UNIX second of that chain's first round, which gives every round its time without asking the network.",
    },
    {
      name: "BEACON.period_seconds",
      value: `${policy.BEACON.period_seconds} seconds`,
      means: "The chain's round interval.",
    },
  ];

  const evidence: Row[] = [
    {
      name: "REPRODUCTION_RUNS",
      value: String(policy.REPRODUCTION_RUNS),
      means:
        "n in the n-of-k evidence rule: how many times a validator runs the frozen prompt or probe.",
    },
    {
      name: "REPRODUCTION_HOLDS",
      value: String(policy.REPRODUCTION_HOLDS),
      means:
        "k in the n-of-k rule: the claim holds when the predicate held in at least this many of those runs.",
    },
    {
      name: "NORM_VERSION",
      value: policy.NORM_VERSION,
      means:
        "The snapshot normalization rule in force at submission. Every hash on an entry is computed under the version the entry was signed with, never a later one.",
    },
    {
      name: "SCHEMA_VERSION",
      value: policy.SCHEMA_VERSION,
      means:
        "The entry schema version in force: what a new entry is written and checked against, and what the offline verifier names when it meets a core sealed under an older one. A core carrying no domain key was sealed under v0.6 and is read as the default domain rather than rewritten.",
    },
    {
      name: "FETCH_MAX_REDIRECTS",
      value: String(policy.FETCH_MAX_REDIRECTS),
      means:
        "Redirects one capture follows. A longer chain is not pinned, it is chased, so the fetch is refused.",
    },
    {
      name: "FETCH_TIMEOUT_MS",
      value: `${policy.FETCH_TIMEOUT_MS} ms`,
      means: "When a capture gives up on the source.",
    },
    {
      name: "CAPTURE_MAX_BYTES",
      value: `${policy.CAPTURE_MAX_BYTES} bytes`,
      means:
        "The largest response body that is archived. Past this size a citation is a download rather than a page to pin.",
    },
  ];

  const release: Row[] = [
    {
      name: "RELEASE_WINDOW_DAYS",
      value: `${policy.RELEASE_WINDOW_DAYS} days`,
      means:
        "Zero, and there is no code behind it any more (decisions D-100 and D-127): the record is free from the seal. Every entry and every event is released the moment it is sealed — its content public, CC0 and in the daily mirror from that instant, served to anyone who asks for it. The proof was public from the first minute either way: every hash, seal and anchor, every operator record, and each entry's id, domain, subject, category, status, effective tier, entry hash, seal object, signers and release date. An unsealed event is not released at all. The number is still published here and still written into every mirror manifest, because a clone carries the window it was made under and readers of v1, v2 and v3 clones read that column.",
    },
  ];

  const access: Row[] = [
    ...Object.entries(policy.RATE_TIERS).map(([slug, tier]) => ({
      name: `RATE_TIERS.${slug}`,
      value: `${tier.name} · ${tier.reads_per_day} reads per day · ${
        tier.key ? "key" : "no key"
      }`,
      means: tier.key
        ? `A keyed tier: ${tier.reads_per_day} reads per UTC day, counted per key. A cap and nothing else — no read is priced anywhere in this record, so a key is a free identity a reader asks for at the free door and a tier buys nothing at all.`
        : `The tier a reader gets without asking for anything: ${tier.reads_per_day} reads per UTC day, counted per client and served with no key at all. Section 9's "free to read at low volume, forever".`,
    })),
    {
      name: "FREE_TIER",
      value: policy.FREE_TIER,
      means:
        "Which of the tiers above is the one a request with no key is served on.",
    },
    {
      name: "FREE_READS_PER_DAY_GLOBAL",
      value: `${policy.FREE_READS_PER_DAY_GLOBAL} reads per day`,
      means:
        "The free tier's ceiling across every client in one UTC day, counted in a scope of its own and checked before the per-client cap above. The per-client cap bounds one reader; this bounds all of them together, so a crowd of addresses each under their own cap cannot be the whole day's budget. It bounds the free tier only: a key and a registered operator are counted under their own caps and are never refused because strangers were reading. Past it the answer is 429 rate_limited with scope: global beside the usual fields.",
    },
    {
      name: "OPERATOR_READS_PER_DAY",
      value: `${policy.OPERATOR_READS_PER_DAY} reads per day`,
      means:
        "How many reads one registered operator's signed requests are served in a UTC day. A signed request names who is asking, so it is metered under that name — its own bucket, keyed by operator id — rather than in the anonymous bucket of whatever address it came from, where a validator walking the log used to spend the free tier for everybody behind it. The served response carries x-nomankind-tier: operator with this limit and what is left of it.",
    },
    {
      name: "ALERT_ENDPOINTS_PER_KEY",
      value: String(policy.ALERT_ENDPOINTS_PER_KEY),
      means:
        "How many live webhook endpoints one key may hold. A sixth is refused endpoint_limit; deleting one frees the slot.",
    },
    {
      name: "ALERT_TIMEOUT_MS",
      value: `${policy.ALERT_TIMEOUT_MS} ms`,
      means:
        "How long one alert delivery may take before it is abandoned and counted as a failed attempt.",
    },
    {
      name: "ALERT_RETRY_MINUTES",
      value: policy.ALERT_RETRY_MINUTES.join(", "),
      means:
        "The retry ladder, in minutes from the attempt that failed: attempt n schedules the next at now plus the nth entry, and past the last entry the delivery is failed rather than retried forever.",
    },
    {
      name: "ALERT_EVENTS_PER_RUN",
      value: String(policy.ALERT_EVENTS_PER_RUN),
      means:
        "How many sealed events past its cursor one run of the alert step derives alerts from. A backlog is not dropped: the next run starts where this one stopped.",
    },
    {
      name: "ALERT_DELIVERIES_PER_RUN",
      value: String(policy.ALERT_DELIVERIES_PER_RUN),
      means:
        "How many due deliveries one run posts, oldest first. Each may take ALERT_TIMEOUT_MS, so the bound is what keeps one dead endpoint from holding a whole run.",
    },
    {
      name: "ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE",
      value: String(policy.ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE),
      means:
        "How many consecutive timed-out deliveries turn an endpoint off. Its pending deliveries are then failed endpoint_disabled, and GET /keys/me/webhooks shows the holder that it is no longer enabled.",
    },
    {
      name: "ALERT_KINDS",
      value: policy.ALERT_KINDS.join(", "),
      means:
        "The seven moments in an entry's life a subscriber can be told about. Every one of them is a fact already in the sealed log, so an alert is a notification of something public and never a fact of its own.",
    },
  ];

  // The tiers standing gates participation with (decision D-130). Three rows
  // for the three tiers, in the order the module publishes them, each printing
  // the same sentence the operator page prints beside a tier; then the two
  // thresholds a tier is decided by, and the one window a senior tier opens.
  const tiers: Row[] = [
    {
      name: "TIERS",
      value: policy.TIERS.join(" · "),
      means:
        "The tiers, in order, lowest first. A tier is a reading of standing and is never stored: tierOf answers it from the number the published formula returned and whether the log has trusted the operator, so it moves the moment the standing does. It gates participation — how much may be written, whether the draw reaches this operator, whether it may dispute — and gates nothing about truth.",
    },
    ...policy.TIERS.map((tier) => ({
      name: `TIERS.${tier}`,
      value: tier,
      means: tierAllows(tier),
    })),
    {
      name: "STANDING_TRUSTED_ENTRY",
      value: `${policy.STANDING_TRUSTED_ENTRY} standing`,
      means:
        "The standing a registered, non-maintainer, non-provider operator reaches to leave probation: at or above it the operator is established, and the log may trust it into the pool. Being in the pool establishes an operator too, whatever its number, because the maintainer names the bootstrap operators into it at genesis and a naming grants trust and no standing. Below STANDING_TRUSTED_STAY a trusted operator loses the trust again, and the gap between the two is what keeps an operator sitting on the bar from flapping in and out.",
    },
    {
      name: "STANDING_SENIOR",
      value: `${policy.STANDING_SENIOR} standing`,
      means:
        "The standing that makes an established operator senior: the highest write cap, the early-access window on a new domain below, and the vote. Like every threshold here it is a reading of the published formula and never a grant.",
    },
    {
      name: "DOMAIN_EARLY_ACCESS_DAYS",
      value: `${policy.DOMAIN_EARLY_ACCESS_DAYS} days`,
      means:
        "How long a newly registered domain is open to senior operators before it opens to everyone. Access by contribution, and a window rather than a gate: the domain is public from the day it is registered, and what the window holds back is the right to join it as an operator.",
    },
  ];

  // The governance vote (decision D-130 item 4, decision D-131 item 2). The
  // window and the ceiling are numbers; the questions are the policy itself,
  // one row each, with the options they were opened with. Every value is read
  // off the frozen object, this page holds none, and the tally each question has
  // drawn is on the votes page rather than here — policy publishes the question
  // and the log answers it.
  const vote: Row[] = [
    {
      name: "VOTE_WINDOW_DAYS",
      value: `${policy.VOTE_WINDOW_DAYS} days`,
      means:
        "How long a question stays open from the day it was opened. A vote cast after it closes is refused rather than counted late, and the window is on the question rather than on the voter: everybody has the same days.",
    },
    {
      name: "VOTE_QUESTIONS_OPEN_MAX",
      value: String(policy.VOTE_QUESTIONS_OPEN_MAX),
      means:
        "How many questions may be open at once. A ceiling rather than a rule of the record: a governance surface that asked a dozen things at a time would be asking nothing, and the senior operators' attention is the scarce thing here.",
    },
    ...policy.VOTE_QUESTIONS.map((question) => ({
      name: `VOTE_QUESTIONS.${question.id}`,
      value: `opened ${question.opened_at} · ${question.options.join(" | ")}`,
      means: `${question.text} It is about ${
        question.about.length === 0 ? "nothing else published" : question.about.join(", ")
      }. The tally is on the votes page, folded from the sealed vote_cast events, and it is advisory to the maintainer until the record's hosting decentralizes.`,
    })),
  ];

  const standing: Row[] = [
    {
      name: "STANDING_VALIDATION_VOLUNTEERED",
      value: `${policy.STANDING_VALIDATION_VOLUNTEERED} standing`,
      means:
        "Earned for a completed validation nobody was drawn for, and for a reconfirmation, which is a check volunteered the same way.",
    },
    {
      name: "STANDING_VALIDATION_ASSIGNED",
      value: `${policy.STANDING_VALIDATION_ASSIGNED} standing`,
      means:
        "Earned for a completed validation the beacon assigned. Assigned work weighs highest, which is what makes an assignment on an entry nobody will read worth doing.",
    },
    {
      name: "STANDING_VALIDATION_REPRODUCED",
      value: `${policy.STANDING_VALIDATION_REPRODUCED} standing`,
      means:
        "Earned beside the amount above when the validation's own signed record carries a passing measurement, and likewise for a measured reconfirmation, so the trusted pool tilts toward the operators who run the test rather than accept it. Contribution is the whole of that tilt: nothing is paid for a measurement in anything but standing.",
    },
    {
      name: "STANDING_ATTESTATION_SCORED",
      value: `${policy.STANDING_ATTESTATION_SCORED} standing`,
      means:
        "Earned by the operator behind a drawn scorer when it signs a drift attestation's score. Smaller than an assigned validation because the probes were drawn for the scorer and the answers were already there — and a scorer that never answers burns STANDING_ASSIGNMENT_MISSED, the same burn an unanswered assignment carries.",
    },
    {
      name: "STANDING_SUBMISSION_VERIFIED",
      value: `${policy.STANDING_SUBMISSION_VERIFIED} standing`,
      means:
        "Earned by the submitter's operator the first time an entry actually derives verified, and once per entry however many decisions follow.",
    },
    {
      name: "STANDING_DISPUTE_UPHELD",
      value: `${policy.STANDING_DISPUTE_UPHELD} standing`,
      means:
        "Earned by the challenger when a dispute is upheld, on top of the staked standing coming back. Nothing else moves: an upheld challenge overturns the entry and claws back no money, because no read of it was ever priced.",
    },
    {
      name: "STANDING_REVALIDATION_CHANGED",
      value: `${policy.STANDING_REVALIDATION_CHANGED} standing`,
      means:
        "Earned by the requester when a revalidation check finds the fact changed, on top of the staked standing coming back. Smaller than an upheld dispute because a request carries no citation — it only asks for a check.",
    },
    {
      name: "STANDING_OVERTURNED_SIGNER",
      value: `${policy.STANDING_OVERTURNED_SIGNER} standing`,
      means:
        "Burned from every operator that signed an overturned entry — its author, each approver, each reconfirmer — once each per entry.",
    },
    {
      name: "STANDING_ASSIGNMENT_MISSED",
      value: `${policy.STANDING_ASSIGNMENT_MISSED} standing`,
      means:
        "Burned when an assigned validation or an assigned revalidation goes unanswered past its window.",
    },
    {
      name: "STANDING_TRUSTED_ENTRY",
      value: `${policy.STANDING_TRUSTED_ENTRY} standing`,
      means:
        "What a registered operator must reach to enter the trusted pool. No model provider and no maintainer operator enters it at any standing.",
    },
    {
      name: "STANDING_TRUSTED_STAY",
      value: `${policy.STANDING_TRUSTED_STAY} standing`,
      means:
        "What a trusted operator must stay at or above to keep it. Two numbers rather than one, so an operator sitting exactly at the bar is not trusted and untrusted by turns.",
    },
    {
      name: "STANDING_DECAY_PAUSED",
      value: policy.STANDING_DECAY_PAUSED ? "paused" : "active",
      means:
        "Whether standing decays. Decay is paused and there is no decay term at all, rather than a rate of zero nobody published: the paper hangs decay on work that stops being read, and the day a rate is published it moves by a decision of its own.",
    },
  ];

  const disputes: Row[] = [
    {
      name: "FAILURE_REPORT_THRESHOLD",
      value: String(policy.FAILURE_REPORT_THRESHOLD),
      means:
        "Reports from this many distinct verified operators auto-open a revalidation, on the log's own initiative rather than against anyone's stake.",
    },
    {
      name: "DISPUTE_STAKE_STANDING",
      value: `${policy.DISPUTE_STAKE_STANDING} standing`,
      means:
        "What an operator puts up to file a dispute, in standing, which is the only thing anyone stakes here. An upheld challenge returns it and pays the challenger STANDING_DISPUTE_UPHELD; a failed one forfeits it, so disputes are for evidence.",
    },
    {
      name: "REVALIDATION_REQUEST_STAKE_STANDING",
      value: `${policy.REVALIDATION_REQUEST_STAKE_STANDING} standing`,
      means:
        "What an operator stakes to ask for a check of an entry inside its freshness window. Returned if the fact changed or the request is upgraded into a dispute, lost if the entry holds.",
    },
    {
      name: "REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW",
      value: String(policy.REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW),
      means:
        "How many checks one operator may request on one entry per freshness window, which is what keeps a request from becoming a way to hold an entry permanently under review.",
    },
  ];

  const attestation: Row[] = [
    {
      name: "PROBE_SET_SIZE",
      value: `${policy.PROBE_SET_SIZE} probes`,
      means:
        "Probes drawn for one drift attestation when the log holds at least that many candidates — verified, observed, fresh entries — picked by the same beacon-and-snapshot draw a validator is assigned by, so neither the model's operator nor the maintainer chooses the questions.",
    },
    {
      name: "PROBE_SET_MIN_CANDIDATES",
      value: String(policy.PROBE_SET_MIN_CANDIDATES),
      means:
        "The floor below which no attestation is drawn at all. Between the floor and the size every candidate is drawn, because the observed tier is thin at genesis: an attestation over three probes is a small attestation and never a refused one.",
    },
    {
      name: "ATTESTATION_SCORERS",
      value: String(policy.ATTESTATION_SCORERS),
      means:
        "Operators drawn from the trusted pool to score the model's answers against the log and sign the result. None of them may be under the model's own operator, and no maintainer or provider operator is eligible.",
    },
    {
      name: "ATTESTATION_WINDOW_HOURS",
      value: `${policy.ATTESTATION_WINDOW_HOURS} hours`,
      means:
        "How long an attestation stays open: from the request to the deadline for the model's answers and for its scorers' scores. Past it the sweep records the attestation expired and names the scorers that never scored.",
    },
  ];

  const sealing: Row[] = [
    {
      name: "SEAL_INTERVAL_MINUTES",
      value: `${policy.SEAL_INTERVAL_MINUTES} minutes`,
      means: "How often the log is sealed and the registry head countersigned.",
    },
    {
      name: "SWEEP_INTERVAL_MINUTES",
      value: `${policy.SWEEP_INTERVAL_MINUTES} minutes`,
      means:
        "How often the sweep runs. Operational only: it says how promptly the log catches up, never how long a validator has.",
    },
    {
      name: "WITNESSES_REQUIRED",
      value: String(policy.WITNESSES_REQUIRED),
      means:
        "Distinct pinned operators that must have countersigned the registry head, verifiably, before a seal counts as witnessed.",
    },
    {
      name: "SEAL_MAX_EVENTS",
      value: String(policy.SEAL_MAX_EVENTS),
      means:
        "The most events one seal covers. A longer run is not dropped: the next seal continues from where this one stopped, so the chain stays contiguous.",
    },
    {
      name: "SWEEP_BATCH_STATEMENTS",
      value: String(policy.SWEEP_BATCH_STATEMENTS),
      means:
        "The most statements one database batch carries. An operational limit rather than a rule of the record: a seal covering the ceiling above is one write per entry it covers, so the write is cut into batches the database takes rather than one it may refuse.",
    },
    {
      name: "LEDGER_ENTRIES_PER_RUN",
      value: String(policy.LEDGER_ENTRIES_PER_RUN),
      means:
        "How many of a published day's entries one run of the ledger step walks. Nothing is priced there: the day's read counts are evidence of use and buy nobody anything. A longer day is not dropped — the next run resumes it where this one stopped, and the day's reconciliation is written only once every entry of it has been walked.",
    },
    {
      name: "DUPLICATE_BACKFILL_PER_RUN",
      value: String(policy.DUPLICATE_BACKFILL_PER_RUN),
      means:
        "How many entries written before the duplicate key was a column (migration 0019) one run of the backfill step gives their key. The key is normalized text, which SQL cannot compute, so it is recomputed in code from each entry's own signed core; a longer backlog is not dropped, the next run continues it, and once nothing is left the step is a single bounded read that finds nothing.",
    },
    {
      name: "WITNESS_FILE_TAIL_BYTES",
      value: `${policy.WITNESS_FILE_TAIL_BYTES} bytes`,
      means:
        "How much of a witness's append-only countersignature file is read, from the end.",
    },
    {
      name: "REGISTRY.origin",
      value: policy.REGISTRY.origin,
      means:
        "The founding identity registry whose citizen log carries nomankind's own seal fingerprints.",
    },
    {
      name: "REGISTRY.public_key",
      value: policy.REGISTRY.public_key,
      means:
        "That registry's Ed25519 public key, pinned so a countersignature can be rechecked offline years later against the same key the collector used.",
    },
    {
      name: "REGISTRY.log",
      value: policy.REGISTRY.log,
      means: "Which of the registry's logs carries identity events.",
    },
    {
      name: "REGISTRY.seal_label",
      value: policy.REGISTRY.seal_label,
      means: "The label every nomankind seal is filed under there.",
    },
  ];

  const status: Row[] = [
    {
      name: "STATUS_ATTENTION_AFTER_INTERVALS",
      value: `${policy.STATUS_ATTENTION_AFTER_INTERVALS} intervals`,
      means:
        "How many of its own intervals a periodic stage may go without a success before the status page calls for attention. Its own intervals and not a fixed number of minutes, so a stage that runs every five minutes and a stage that runs once a day are judged by the same rule.",
    },
    {
      name: "STATUS_FAILING_AFTER_MINUTES",
      value: `${policy.STATUS_FAILING_AFTER_MINUTES} minutes`,
      means:
        "How long a broken rule stays attention before the status page calls it failing. Two readings and not one, because a step that skipped once and a step that has been down half an hour are not the same fact, and a page that showed them the same way would be a page nobody could act on.",
    },
  ];

  const mirror: Row[] = [
    {
      name: "MIRROR.repository",
      value: policy.MIRROR.repository,
      means:
        "The public repository the sealed log is exported to once per UTC day (Section 11). Each environment writes its own top-level directory there and touches nothing else, so demo and production share one mirror without either overwriting the other.",
    },
    {
      name: "MIRROR.branch",
      value: policy.MIRROR.branch,
      means:
        "The branch each export commits to. One branch and no history rewriting: an export is a commit on top of what is there, so the repository is itself an append-only record of the exports.",
    },
    {
      name: "MIRROR.license",
      value: policy.MIRROR.license,
      means:
        "The licence the mirrored log is published under. The data was under it before there was a mirror: the export is a convenience, not the licence, and a fork that clones it owes nomankind nothing.",
    },
    {
      name: "MIRROR.api",
      value: policy.MIRROR.api,
      means:
        "The API host the export pushes through. Pinned like every other endpoint the code calls, so a mirror that moved moves by a recorded decision rather than by configuration nobody published.",
    },
    {
      name: "MIRROR.web",
      value: policy.MIRROR.web,
      means:
        "Where a commit is linked for a reader: the host the mirror page's commit link and the API's url field are built from.",
    },
    {
      name: "MIRROR.raw",
      value: policy.MIRROR.raw,
      means:
        "Where an export's own files are fetched from unrendered: the host the raw mirror.json link is built from, which is what a verifier reads rather than a web page about it.",
    },
  ];

  const requests: Row[] = [
    {
      name: "REQUEST_CLOCK_SKEW_SECONDS",
      value: `${policy.REQUEST_CLOCK_SKEW_SECONDS} seconds`,
      means:
        "How far a signed write request's timestamp may sit from the verifier's clock, in either direction, before it is refused.",
    },
    {
      name: "NONCE_RETENTION_SECONDS",
      value: `${policy.NONCE_RETENTION_SECONDS} seconds`,
      means:
        "How long a spent nonce is remembered. Twice the skew window, so no request the clock rule still accepts can be replayed after its nonce is forgotten.",
    },
    {
      name: "LIST_PAGE_LIMIT",
      value: String(policy.LIST_PAGE_LIMIT),
      means: "The most records one list request returns.",
    },
    {
      name: "HOME_LATEST_ENTRIES",
      value: String(policy.HOME_LATEST_ENTRIES),
      means: "How many entries the home page's latest-sealed row shows.",
    },
    {
      name: "LANDING_BAND_SEALS",
      value: String(policy.LANDING_BAND_SEALS),
      means: "How many seals the landing page's live seal-chain band shows.",
    },
    {
      name: "SITEMAP_MAX_ENTRIES",
      value: String(policy.SITEMAP_MAX_ENTRIES),
      means:
        "The most entry URLs one /sitemap.xml carries, newest submission first. A bound on the document rather than a rule of the record: a sitemap that grew with the log would be a read of the whole table dressed as a file.",
    },
    {
      name: "PAGE_CACHE_SECONDS",
      value: `${policy.PAGE_CACHE_SECONDS} seconds`,
      means:
        "How long an anonymous page may be served from the edge cache. Operational rather than a rule of the record: it says how far behind the log a page may be, never what anything costs or what anyone is allowed. The JSON doors are not cached at any number.",
    },
    {
      name: "PAGE_CACHE_STALE_SECONDS",
      value: `${policy.PAGE_CACHE_STALE_SECONDS} seconds`,
      means:
        "How long past that a stale copy may be served while a fresh one is fetched.",
    },
  ];

  const allKeys = Object.keys(policy).sort((a, b) => (a < b ? -1 : 1));
  const values = policy as unknown as Record<string, unknown>;
  const allJson = `{\n${allKeys
    .map((key) => `  ${JSON.stringify(key)}: ${JSON.stringify(values[key])}`)
    .join(",\n")}\n}`;

  return layout(ctx, {
    title: "Policy",
    description: "Every published number the record runs on, grouped.",
    body: html`
      <div class="page-head"><h1>Policy</h1></div>
      <p class="lede">
        Every published number, grouped. These are policy, not code constants
        that happen to be visible: each moves only by a recorded decision, and a
        change applies to entries submitted after it, never to entries already
        sealed. The same object is served as JSON at
        <a href="/policy">GET /policy</a> with
        <span class="mono">Accept: application/json</span>, straight from the one
        module the kernel reads, so a reader can check that this page and the
        running code hold the same values.
      </p>

      ${group("Validation", validation)}
      ${group("Community operators", community)}
      <p class="note">
        Two paths to being a validator, one registry (decision D-138). A
        community operator's lines are validations and count in consensus like a
        domain operator's, under the Sybil floors above: a consensus met by
        community operators alone needs
        ${policy.COMMUNITY_MIN_ACCOUNTS} distinct bound accounts, from
        ${policy.COMMUNITY_MIN_COMMUNITIES} distinct communities once more than
        one community counts, and no more than
        ${communityCapPerEntry(counting.length)} of one entry's counted
        community validations may come from a single community. Every verified
        entry discloses which kinds met it, and
        <a href="/entries">the listing</a> takes
        <span class="mono">min_class</span> as a floor on that word.
      </p>
      ${group("Evidence", evidence)}
      ${Object.entries(policy.DOMAINS).map(
        ([slug, domain]) =>
          html`${domainPanel(slug, domain)}${sourcesPanel(slug, domain)}`,
      )}
      ${group("Release", release)} ${group("Access and alerts", access)}
      ${contributionTable(policy)}

      <p class="note">
        The record is free (decision D-127). Every event and every entry is
        released the moment it is sealed, its content public and CC0 from that
        instant, and no read of it is priced: there is no paid tier, no key
        purchase, no read-share slot and no fee anywhere in this table. What the
        contribution table above shows is rate and nothing else — a tier is a
        daily count, a key is a free identity a reader asks for at the free door
        so alerts, receipts by counter and usage listings have something to
        name, and the caps are what keep one reader from being the whole day.
      </p>

      ${group("Tiers", tiers)} ${group("Vote", vote)}

      <p class="note">
        The vote is the senior tier's (decision D-130 item 4), and
        <a href="/votes">the votes page</a> shows every question with its tally
        and every voter by name. One vote per operator and one per disclosed
        perimeter, and the tally is advisory to the maintainer until the
        record's hosting decentralizes: one party still runs the Worker, the
        database and the keys, so a vote that called itself binding would be
        claiming a power nobody can check.
      </p>

      ${group("Standing", standing)}
      ${group("Disputes and reports", disputes)}
      ${group("Attestation", attestation)}

      <p class="note">
        Those numbers and the two stakes below are the whole standing formula:
        nothing else in the log moves standing, so a reader can fold the sealed
        events themselves and get the same number the log shows. Standing is not
        a score nomankind assigns — it is derived from the log, and a stored
        standing that disagrees with the log is wrong.
      </p>

      <p class="note">
        Every stake above is standing and every amount is a placeholder the
        maintainer set, moving only by a later recorded decision. Nothing is
        staked in money, because there is no money here to stake: a dispute and a
        revalidation request both put up contribution, and that is what an
        upheld challenge returns and a failed one forfeits.
      </p>

      ${group("Sealing and anchoring", sealing)}

      <section class="panel">
        <h2 class="panel-title">WITNESS_PIN</h2>
        <p class="note">
          The witnesses whose countersignatures are counted, pinned by operator
          and by key. The registry's own directory is a pointer and never an
          endorsement, so a row that moved is dropped for that run and re-pinned
          only by decision. None of them is nomankind's, so no two accepted
          countersignatures can be under common control.
        </p>
        <p class="note">
          The bar in full: a published key, no two under common control,
          nomankind ineligible to be one, and no pinned witness may be an
          operator of the record or under the control of one. The last clause is
          the one this table cannot show on its own, so
          <a href="/independence">the independence page</a> publishes the
          validator set beside this one and the intersection of the two.
        </p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>operator</th>
                <th>key</th>
                <th>source</th>
              </tr>
            </thead>
            <tbody>
              ${policy.WITNESS_PIN.map(
                (pin) => html`<tr>
                  <td class="mono">${pin.operator}</td>
                  <td class="mono">${pin.public_key}</td>
                  <td class="mono">${pin.url}</td>
                </tr>`,
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel">
        <h2 class="panel-title">ANCHOR_CALENDARS</h2>
        <p class="note">
          The external timestamping calendars each day's batch hash is offered
          to, in order. The first that answers is the one recorded, which is what
          makes the existence proof independent of the identity layer.
        </p>
        <div class="table-wrap">
          <table class="table">
            <tbody>
              ${listRows("ANCHOR_CALENDARS", policy.ANCHOR_CALENDARS)}
            </tbody>
          </table>
        </div>
      </section>

      ${group("Status", status)}

      <p class="note">
        Those two are the whole of the status page's judgement: every light on
        <a href="/status">the status page</a> is one of the published rules
        beside it applied to the log and to the sweep's stored report, and these
        are the only numbers that decide when a rule that has been broken stops
        being a hiccup. They are operational and they move by decision like every
        other number here.
      </p>

      ${group("Mirror", mirror)}

      <p class="note">
        The mirror is the exit (Section 11): the sealed log is exported daily to
        that repository under that licence, and
        <a href="/mirror/latest">the mirror page</a> says what this environment
        last pushed. Nothing here decides what is exported — the sealed record
        does — and no number is needed for it: the export is owed once per UTC
        day, and how long it may be owed is the status page's
        STATUS_FAILING_AFTER_MINUTES above.
      </p>

      ${group("Requests", requests)}

      <section class="panel">
        <h2 class="panel-title">All keys</h2>
        <p class="note">
          Every key of the policy object, enumerated rather than listed by hand,
          so a number added later appears here whether or not it was given a row
          above. This is the object <span class="mono">GET /policy</span> serves.
        </p>
        <pre class="block mono">${allJson}</pre>
      </section>
    `,
  });
}

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

import type { DomainPolicy, POLICY } from "../../policy.js";
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
 * Micro-USD per dollar, and reads per thousand reads. Units and not policy
 * numbers: the first is what a millionth of a dollar means (src/ledger.ts) and
 * the second is what "per thousand" means. Every amount they are applied to is
 * read from POLICY.
 */
const MICROS_PER_DOLLAR = 1_000_000;
const READS_PER_THOUSAND = 1_000;

/** A micro-USD amount as dollars, by integer arithmetic and never a float. */
function dollars(micros: number): string {
  const whole = Math.trunc(micros / MICROS_PER_DOLLAR);
  const fraction = micros % MICROS_PER_DOLLAR;
  const cents = Math.trunc(fraction / (MICROS_PER_DOLLAR / 100));
  const remainder = fraction % (MICROS_PER_DOLLAR / 100);
  return remainder === 0
    ? `$${whole}.${String(cents).padStart(2, "0")}`
    : `$${whole}.${String(fraction).padStart(6, "0")}`;
}

/** The paper's own worked figure, derived from the price rather than restated. */
function dollarsPerThousandReads(microsPerRead: number): string {
  return dollars(microsPerRead * READS_PER_THOUSAND);
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

  const money: Row[] = [
    {
      name: "HOLDBACK_DAYS",
      value: `${policy.HOLDBACK_DAYS} days`,
      means:
        "How long accrued fees are held before payout, so an upheld dispute can claw them back before they leave.",
    },
    ...Object.entries(policy.READ_SHARE_SPLIT).map(([tier, split]) => ({
      name: `READ_SHARE_SPLIT.${tier}`,
      value: `submitter ${split.submitter} percent · validator ${split.validator} percent`,
      means:
        tier === "observed"
          ? "Section 9, on an observed entry: the submitter's share and each read-share slot holder's share of paid-read revenue, both larger than the stated row above, so the operators who measure are paid more than the operators who copy (Section 4). A slot holder takes this validator rate only when its own signed record carried a passing measurement; one that accepted the test without running it takes the stated rate beside it. The difference between the two rows comes out of nomankind's share and never out of the reader's price, which is one number per read whatever tier the entry is."
          : "Section 9's launch split, on a stated entry: the submitter's share and each read-share slot holder's share of paid-read revenue. The tier that prices an entry is the one fixed when it verified, so a split that moved by decision never reprices a read that was already published.",
    })),
    {
      name: "SLOT_COUNT",
      value: String(policy.SLOT_COUNT),
      means:
        "Read-share slots on an entry. A reconfirmation rotates the oldest holder out rather than adding one, so the share is always split among one submitter and this many slot holders.",
    },
    {
      name: "READ_PRICE_MICROS_PER_READ",
      value: `${policy.READ_PRICE_MICROS_PER_READ} micro-USD per read`,
      means:
        `The price a paid read is charged at, and the number every read share is computed from: ${dollarsPerThousandReads(policy.READ_PRICE_MICROS_PER_READ)} per thousand reads. Micro-USD, a millionth of a dollar, because one read's submitter share is a fraction of a cent and a ledger that rounded it to cents would pay the long tail nothing.`,
    },
    {
      name: "CONTRIBUTOR_SHARE_FLOOR_PERCENT",
      value: `${policy.CONTRIBUTOR_SHARE_FLOOR_PERCENT} percent`,
      means:
        "Section 9: the contributor share is a floor that only rises. So the floor is published as a number of its own, and every tier's share beside it is checked against it — a share below this would be a broken promise rather than a smaller payment.",
    },
    ...Object.entries(policy.CONTRIBUTOR_SHARE_PERCENT).map(
      ([tier, percent]) => ({
        name: `CONTRIBUTOR_SHARE_PERCENT.${tier}`,
        value: `${percent} percent`,
        means: `The contributor pool's share of paid-read revenue on a ${tier} entry today: at or above the floor above, and exactly the split it is made of (one READ_SHARE_SPLIT.${tier}.submitter share and SLOT_COUNT READ_SHARE_SPLIT.${tier}.validator shares). It rises on published milestones and never falls.`,
      }),
    ),
    {
      name: "PAYOUT_MINIMUM_MICROS",
      value: `${policy.PAYOUT_MINIMUM_MICROS} micro-USD`,
      means:
        `How small a released balance is carried forward instead of paid: ${dollars(policy.PAYOUT_MINIMUM_MICROS)}. Nothing is written off, because a transfer that cost more than it paid would take the difference out of the contributor pool (decision D-053).`,
    },
    {
      name: "PAYOUT_CYCLE",
      value: policy.PAYOUT_CYCLE,
      means:
        "How often payouts run: one UTC calendar month per cycle, per operator (decision D-053).",
    },
  ];

  const paid: Row[] = [
    ...Object.entries(policy.RATE_TIERS).map(([slug, tier]) => ({
      name: `RATE_TIERS.${slug}`,
      value: `${tier.name} · ${tier.reads_per_day} reads per day · ${
        tier.key ? "key" : "no key"
      }`,
      means: tier.key
        ? `A paid tier: ${tier.reads_per_day} reads per UTC day, counted per key. A tier buys throughput and never a discount — every paid read is priced at READ_PRICE_MICROS_PER_READ whichever tier bought it.`
        : `The tier a reader gets without asking for anything: ${tier.reads_per_day} reads per UTC day, counted per client and served with no key at all. Section 9's "free to read at low volume, forever".`,
    })),
    {
      name: "FREE_TIER",
      value: policy.FREE_TIER,
      means:
        "Which of the tiers above is the one a request with no key is served on.",
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
      name: "ALERT_KINDS",
      value: policy.ALERT_KINDS.join(", "),
      means:
        "The seven moments in an entry's life a subscriber can be told about. Every one of them is a fact already in the sealed log, so an alert is a notification of something public and never a fact of its own.",
    },
    {
      name: "STRIPE.api",
      value: policy.STRIPE.api,
      means:
        "The payment provider's API host (decision D-078). Pinned here for the reason MIRROR and REGISTRY are: an address the system depends on is a published choice, not an adapter's private detail. No secret is here — the key and the webhook signing secret are Worker secrets and never appear in this repository.",
    },
    {
      name: "STRIPE.meter_event_name",
      value: policy.STRIPE.meter_event_name,
      means:
        "The provider's meter each day's published paid reads are reported under, one event per key per day.",
    },
    {
      name: "STRIPE.price_lookup_prefix",
      value: policy.STRIPE.price_lookup_prefix,
      means:
        "A price's lookup key is this prefix, the environment and the tier, so demo and production cannot buy each other's prices.",
    },
    {
      name: "STRIPE.currency",
      value: policy.STRIPE.currency,
      means: "The currency every price is created in.",
    },
    {
      name: "STRIPE.webhook_tolerance_seconds",
      value: `${policy.STRIPE.webhook_tolerance_seconds} seconds`,
      means:
        "How far a provider webhook's own timestamp may sit from this Worker's clock before the message is refused as stale, so a captured message cannot be replayed later.",
    },
    {
      name: "STRIPE.webhook_path",
      value: policy.STRIPE.webhook_path,
      means:
        "The one path the provider knocks on. It trusts nothing it is sent until the signature over the raw body verifies, and it may change exactly one column: a key's status.",
    },
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
        "Earned beside the amount above when the validation's own signed record carries a passing measurement, and likewise for a measured reconfirmation, so the trusted pool tilts toward the operators who run the test rather than accept it. The money side of the same rule is READ_SHARE_SPLIT.observed above.",
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
        "Earned by the challenger when a dispute is upheld, on top of the stake coming back.",
    },
    {
      name: "STANDING_REVALIDATION_CHANGED",
      value: `${policy.STANDING_REVALIDATION_CHANGED} standing`,
      means:
        "Earned by the requester when a revalidation check finds the fact changed, on top of the stake coming back. Paid in standing because the stake was standing, and smaller than an upheld dispute because a request carries no citation — it only asks for a check.",
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
        "Whether standing decays. Decay is paused until the paid loop starts, since before then there is nothing for it to decay against — so there is no decay term at all, rather than a rate of zero nobody published.",
    },
  ];

  const disputes: Row[] = [
    {
      name: "FAILURE_REPORT_THRESHOLD",
      value: String(policy.FAILURE_REPORT_THRESHOLD),
      means:
        "Reports from this many distinct verified operators auto-open a revalidation, at nomankind's expense rather than anyone's stake.",
    },
    {
      name: "DISPUTE_STAKE_STANDING",
      value: `${policy.DISPUTE_STAKE_STANDING} standing`,
      means:
        "What a registered operator puts up to file a dispute. An upheld challenge returns it and pays the challenger; a failed one forfeits it, so disputes are for evidence.",
    },
    {
      name: "DISPUTE_FILING_FEE_CENTS",
      value: `${policy.DISPUTE_FILING_FEE_CENTS} cents`,
      means:
        "What a bare key puts up instead: a refundable filing fee, so a burner key cannot dispute for free.",
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

      ${group("Validation", validation)} ${group("Evidence", evidence)}
      ${Object.entries(policy.DOMAINS).map(
        ([slug, domain]) =>
          html`${domainPanel(slug, domain)}${sourcesPanel(slug, domain)}`,
      )}
      ${group("Money and standing", money)} ${group("Paid access", paid)}

      <p class="note">
        Section 9: "The log is free to read at low volume, forever. Revenue
        comes from high-rate API access, structured feeds and webhooks, change
        alerts." The free row above is that sentence's first half and carries no
        key at all; the paid rows are its second. A tier is a daily cap and
        nothing else — the price per read is the same on every one of them, so a
        tier buys throughput and never a discount.
      </p>

      ${group("Standing", standing)} ${group("Disputes and reports", disputes)}
      ${group("Attestation", attestation)}

      <p class="note">
        Those numbers and the two stakes below are the whole standing formula:
        nothing else in the log moves standing, so a reader can fold the sealed
        events themselves and get the same number the log shows. Standing is not
        a score nomankind assigns — it is derived from the log, and a stored
        standing that disagrees with the log is wrong.
      </p>

      <p class="note">
        Every stake above is a placeholder the maintainer set, and a stake is a
        ledger record and nothing else until the money side is built: no money
        moves on any of them, and the maintainer sets the real amounts by a later
        recorded decision.
      </p>

      <p class="note">
        There is no seed fee: contributors are paid only from read revenue
        (decision D-052). The maintainer pays nothing from its own funds, and
        validating before there is revenue earns standing and read-share slots
        on the entries validated, which pay from the first paid read.
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

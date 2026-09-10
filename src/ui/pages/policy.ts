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
    {
      name: "READ_SHARE_SPLIT.submitter",
      value: `${policy.READ_SHARE_SPLIT.submitter} percent`,
      means: "The submitter's share of paid-read revenue on their entry.",
    },
    {
      name: "READ_SHARE_SPLIT.validator",
      value: `${policy.READ_SHARE_SPLIT.validator} percent`,
      means: "Each read-share slot holder's share of paid-read revenue.",
    },
    {
      name: "SLOT_COUNT",
      value: String(policy.SLOT_COUNT),
      means:
        "Read-share slots on an entry. A reconfirmation rotates the oldest holder out rather than adding one, so the share is always split among one submitter and this many slot holders.",
    },
    {
      name: "CONTRIBUTOR_SHARE_PERCENT",
      value: `${policy.CONTRIBUTOR_SHARE_PERCENT} percent`,
      means:
        "The contributor pool's share of paid-read revenue at launch. It is a floor that only rises, on published milestones, and never falls.",
    },
    {
      name: "READ_PRICE_MICROS_PER_READ",
      value: `${policy.READ_PRICE_MICROS_PER_READ} micro-USD per read`,
      means:
        `The price a paid read is charged at, and the number every read share is computed from: ${dollarsPerThousandReads(policy.READ_PRICE_MICROS_PER_READ)} per thousand reads. Micro-USD, a millionth of a dollar, because one read's submitter share is a fraction of a cent and a ledger that rounded it to cents would pay the long tail nothing.`,
    },
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
    {
      name: "paid read tiers and their rate limits",
      value: "not yet published (M24)",
      means:
        "Reads are free at low volume today. The price above is published policy; the paid tiers and the rate limits that go with them arrive with M24.",
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
        "What an operator stakes to ask for a check of an entry inside its freshness window. Returned with a reward if the fact changed, lost if the entry holds.",
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
      ${Object.entries(policy.DOMAINS).map(([slug, domain]) =>
        domainPanel(slug, domain),
      )}
      ${group("Money and standing", money)}
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

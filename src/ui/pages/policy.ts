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

import type { POLICY } from "../../policy.js";
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
 * The page.
 *
 * `policy` is the whole frozen object rather than the individual constants: a
 * page handed the object cannot print a number the object does not hold, and
 * the last block can enumerate it.
 */
export function renderPolicy(ctx: PageContext, policy: typeof POLICY): string {
  const staleness = Object.entries(policy.STALENESS_WINDOW_DAYS).map(
    ([category, days]) => ({
      name: `STALENESS_WINDOW_DAYS.${category}`,
      value: days === null ? "no window (event category)" : `${days} days`,
      means:
        days === null
          ? `An entry in the ${category} category carries no freshness window: once it happened it stays true, so it never goes stale.`
          : `A ${category} entry expires ${days} days after its last confirmation, and reads on it are marked stale until a trusted operator reconfirms it.`,
    }),
  );

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
      name: "FAILURE_REPORT_THRESHOLD",
      value: String(policy.FAILURE_REPORT_THRESHOLD),
      means:
        "Reports from this many distinct verified operators auto-open a revalidation.",
    },
    {
      name: "the standing formula and its decay rate",
      value: "not yet published (M21)",
      means:
        "Standing is derived from the sealed events by a published formula, so anyone can recompute anyone's standing and get the same number. Decay is paused until the paid loop starts. Neither the formula nor the rate is published yet.",
    },
    {
      name: "the payout minimum and the payout cycle",
      value: "not yet published (M21, decision D-053)",
      means:
        "How small a balance is carried forward instead of paid, and how often payouts run. Needs data from the first months of operation.",
    },
    {
      name: "paid read tiers and the price per thousand reads",
      value: "not yet published (M24)",
      means:
        "Reads are free at low volume today. The paid tiers, their rate limits and the price the contributor share is computed against arrive with M24.",
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
      ${group("Freshness", staleness)} ${group("Money and standing", money)}

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
        <h2 class="panel-title">MODEL_PROVIDER_DOMAINS</h2>
        <p class="note">
          The published list of model providers' registrable domains. A
          registration on one of them, or on any subdomain of one, is refused at
          the door. It is the cheap first check and never the whole enforcement:
          the signed independence attestation and the public record behind it are
          what actually bind (Section 10).
        </p>
        <div class="table-wrap">
          <table class="table">
            <tbody>
              ${listRows("MODEL_PROVIDER_DOMAINS", policy.MODEL_PROVIDER_DOMAINS)}
            </tbody>
          </table>
        </div>
      </section>

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

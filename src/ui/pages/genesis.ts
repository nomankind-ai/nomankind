/**
 * Genesis: how the founding trusted pool is seeded, and who is in it
 * (Whitepaper Section 11).
 *
 * The one page on this site that asks the reader for something. It is still a
 * record rather than a pitch: the three joining steps are the three the paper
 * names, the attestation is shown as the exact string an operator signs rather
 * than a paraphrase of it, and the table below is whatever this environment's
 * log actually holds — an empty pool says so instead of showing a plan.
 *
 * The call itself is an issue in the code repository, opened at production
 * go-live. Until then the placeholder below is plain text and not a link: a
 * link to a page that does not exist is a promise the log cannot keep.
 */

import { VERIFICATION_MIN_OUTSIDE_OPERATORS } from "../../policy.js";
import { fmtInstant, html, layout } from "../html.js";
import type { GenesisData, PageContext } from "../types.js";

/** The placeholder that stands where the call's issue link will go (M25). */
const ISSUE_PLACEHOLDER =
  "[ISSUE LINK: the genesis call is opened in the repository at production go-live, M25]";

export function renderGenesis(ctx: PageContext, data: GenesisData): string {
  const txtRecordForm = `${data.txtRecordPrefix}.<domain>`;

  const rows =
    data.rows.length === 0
      ? html`<tr>
          <td colspan="5" class="muted">
            No operators registered on this environment.
          </td>
        </tr>`
      : html`${data.rows.map(
          (row) => html`<tr>
            <td class="mono">${row.operator}</td>
            <td class="mono">${row.registeredSeq}</td>
            <td class="mono">
              ${row.trustedSeq === null ? "not named" : row.trustedSeq}
            </td>
            <td class="mono">${row.validations}</td>
            <td class="mono">${fmtInstant(row.lastValidationAt)}</td>
          </tr>`,
        )}`;

  const maintainerLine = data.maintainerConfigured
    ? "The maintainer key is set on this environment, so genesis naming can be called here."
    : "Genesis naming is not configured until production go-live (M25): without a maintainer key, POST /genesis answers 503 maintainer_not_configured rather than naming anyone.";

  return layout(ctx, {
    title: "Genesis",
    description:
      "The call for founding trusted operators, and who has registered.",
    body: html`
      <div class="page-head"><h1>Call for genesis operators</h1></div>
      <p class="lede">
        Nothing in this log can reach verified until
        ${VERIFICATION_MIN_OUTSIDE_OPERATORS} verified operators outside the
        maintainer's own are live and the trusted pool is non-empty.
        The maintainer seeds that pool once, by naming its first members in
        public — a bootstrap exception to the earned-record rule, stated as such,
        and the only time trusted status is granted rather than earned. Genesis
        operators may not include the maintainer's own, hold no other privilege,
        and keep trusted status the same way everyone after them does, by their
        validation record. Once the pool grows on records alone, the naming power
        lapses.
      </p>

      <section class="panel">
        <h2 class="panel-title">Who is sought</h2>
        <p class="note">
          Independent operators: the parties with the most to gain from a neutral
          record and no stake in any lab. Teams running agents across several
          providers. Independent evaluation and observability shops that already
          measure provider behavior. University groups doing the same. No
          operator under a model provider is eligible — no lab or model provider
          may be a maintainer, funder, or trusted operator — and a registration
          on a provider's domain, or any subdomain of one, is refused at the door
          before anything else is checked.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">Joining takes three steps</h2>
        <dl class="dl">
          <dt>1. Prove a domain</dt>
          <dd>
            The operator id is the domain itself. Publish a DNS TXT record at
            <span class="mono">${txtRecordForm}</span> whose value is exactly
            your 1F916 agent id — <span class="mono">1F916:</span> plus the
            unpadded base64url of your raw Ed25519 public key, and nothing else.
            The check is real on every environment, over DNS-over-HTTPS, and
            refuses <span class="mono">dns_no_record</span> when the label is
            absent and <span class="mono">dns_mismatch</span> when it names
            another key.
          </dd>
          <dt>2. Complete payout onboarding</dt>
          <dd>
            Business verification for a company, identity verification for a
            person, through the payment provider, and hold its reference. Every
            payout lands on a real legal entity, which is what makes a burned
            operator lose a name and a payment record rather than a domain. The
            provider is mocked on local and demo, where references beginning
            <span class="mono">mock-verified-</span> and
            <span class="mono">mock-pending-</span> stand in for it; the real
            provider is wired at production go-live (M25), and until then
            production answers <span class="mono">payout_unavailable</span>.
          </dd>
          <dt>3. Sign the independence attestation</dt>
          <dd>
            Sign the provider-independence attestation with your 1F916 key. The
            text is fixed and signed verbatim, so what an operator put their key
            to is the same string every reader can recheck years later. A false
            attestation burns the operator and is logged in public.
          </dd>
        </dl>
        <p class="note">
          The binding is then sealed into the log and the operator can validate.
          Entry to the trusted pool follows from validation record, except for
          the named genesis members.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">The attestation, verbatim</h2>
        <pre class="block mono">${data.attestationText}</pre>
        <p class="note">
          Version <span class="mono">${data.attestationVersion}</span>. The
          signed bytes are the UTF-8 of the tag
          <span class="mono">nomankind-attestation-v1</span>, a newline, and the
          RFC 8785 canonical JSON of agent, operator, signed_at, text and
          version; the signature is unpadded base64url Ed25519, checked against
          the public key inside the agent id itself.
        </p>
      </section>

      <section class="panel">
        <h2 class="panel-title">Register</h2>
        <p class="note">
          One signed request. The body carries exactly these keys and no others;
          the four <span class="mono">x-nomankind-*</span> headers and the bytes
          they sign are on the <a href="/api">API page</a>, along with every
          refusal this route can answer and the order it applies them in.
        </p>
        <pre class="block mono">POST /operators
{
  "operator": "&lt;your domain&gt;",
  "attestation": {
    "version": "${data.attestationVersion}",
    "signed_at": "&lt;ISO 8601 date-time&gt;",
    "signature": "&lt;unpadded base64url Ed25519&gt;"
  },
  "payout": { "reference": "&lt;your payout onboarding reference&gt;" }
}</pre>
      </section>

      <section class="panel">
        <h2 class="panel-title">The public dry run</h2>
        <p class="note">
          Each candidate validates one seeded entry in public before being named,
          so the genesis pool is named on a record and not a promise. This is
          what this environment's log holds: who registered, where, whether the
          maintainer has named them, and what they have validated since.
        </p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>operator</th>
                <th>registered at</th>
                <th>named at</th>
                <th>validations</th>
                <th>last validation</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
        <p class="note">${maintainerLine}</p>
      </section>

      <section class="panel">
        <h2 class="panel-title">The call</h2>
        <p class="note">
          The call, the dry-run results, and the names of the genesis pool are
          published in the open issue in the code repository.
        </p>
        <p class="note mono">${ISSUE_PLACEHOLDER}</p>
      </section>
    `,
  });
}

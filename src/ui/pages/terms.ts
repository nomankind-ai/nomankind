/**
 * Terms of use and privacy, for a record that is free and takes no payment.
 *
 * Decision D-097 item 2 as rewritten under D-127. The original decision asked
 * for terms of service and a privacy note beside a paid tier; the paid tier is
 * gone, so what is left is the four things a reader of a free record actually
 * needs: what licence the data and the code are under, what warranty there is
 * (none), which rules a caller can be refused under, and what is stored about
 * whom. Nothing on this page is about a transaction, because nothing here is
 * bought: no price, no invoice, no refund, and nothing to cancel.
 *
 * Every sentence on it is true of the code as it stands. The caps are read from
 * src/policy.ts by name, the exclusions are read off the domain registry, and
 * nothing is described here that no door enforces: a terms page that promised a
 * rule nobody applies would be exactly the kind of claim this record exists to
 * refuse. Whitepaper Sections 10 and 11 are the posture this page states in
 * plain words; the paper is linked at the foot of it for the long form.
 *
 * Pure, like every page in src/ui/pages/: no clock, no database, no network.
 */

import {
  ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE,
  ALERT_ENDPOINTS_PER_KEY,
  ALERT_TIMEOUT_MS,
  DOMAIN_SLUGS,
  excludedPartyDomains,
  FREE_READS_PER_DAY_GLOBAL,
  FREE_TIER,
  OPERATOR_READS_PER_DAY,
  RATE_TIERS,
  STANDING_ASSIGNMENT_MISSED,
  STANDING_OVERTURNED_SIGNER,
  WRITES_PER_AGENT_PER_DAY,
  WRITES_PER_AGENT_PER_DAY_PROBATION,
  WRITES_PER_AGENT_PER_DAY_SENIOR,
  WRITES_PER_CLIENT_PER_DAY,
} from "../../policy.js";
import { CONTACT_EMAIL, html, layout, type Safe } from "../html.js";
import type { PageContext } from "../types.js";

/** The data licence, and the one place its name and its deed are written. */
const CC0_URL = "https://creativecommons.org/publicdomain/zero/1.0/";

/** The code licence, linked to the licence text in the repository. */
const APACHE_URL =
  "https://github.com/nomankind-ai/nomankind/blob/main/LICENSE";

/** Cloudflare's own terms, which cover the transport and nothing this record says. */
const CLOUDFLARE_TERMS_URL = "https://www.cloudflare.com/terms/";

/** One published limit: the constant's own name, its value, what it bounds. */
interface Limit {
  readonly name: string;
  readonly value: string;
  readonly bounds: string;
}

/**
 * The caps a caller can actually be refused under, by the names src/policy.ts
 * gives them. Named rather than spelt as sentences, because a reader who wants
 * to check one can read it off `GET /policy` under the same name.
 */
const CAPS: readonly Limit[] = Object.freeze([
  Object.freeze({
    name: `RATE_TIERS.${FREE_TIER}.reads_per_day`,
    value: String(RATE_TIERS[FREE_TIER]!.reads_per_day),
    bounds:
      "Reads in one UTC day from one keyless client, counted under a hashed scope and never an address.",
  }),
  Object.freeze({
    name: "FREE_READS_PER_DAY_GLOBAL",
    value: String(FREE_READS_PER_DAY_GLOBAL),
    bounds:
      "Free reads the whole log serves in one UTC day, across every keyless client at once. It bounds the free tier only: a key and a registered operator are counted in buckets of their own and are never refused because strangers were reading.",
  }),
  Object.freeze({
    name: "RATE_TIERS.standard.reads_per_day",
    value: String(RATE_TIERS["standard"]!.reads_per_day),
    bounds: "Reads in one UTC day under one free key on the standard tier.",
  }),
  Object.freeze({
    name: "RATE_TIERS.high.reads_per_day",
    value: String(RATE_TIERS["high"]!.reads_per_day),
    bounds: "Reads in one UTC day under one free key on the high tier.",
  }),
  Object.freeze({
    name: "OPERATOR_READS_PER_DAY",
    value: String(OPERATOR_READS_PER_DAY),
    bounds:
      "Reads in one UTC day from one registered operator's signed requests, counted under the operator id, which is already public.",
  }),
  Object.freeze({
    name: "WRITES_PER_AGENT_PER_DAY",
    value: String(WRITES_PER_AGENT_PER_DAY),
    bounds: "Writes in one UTC day signed by one agent key at the ordinary tier.",
  }),
  Object.freeze({
    name: "WRITES_PER_AGENT_PER_DAY_PROBATION",
    value: String(WRITES_PER_AGENT_PER_DAY_PROBATION),
    bounds: "Writes in one UTC day signed by one agent key on probation.",
  }),
  Object.freeze({
    name: "WRITES_PER_AGENT_PER_DAY_SENIOR",
    value: String(WRITES_PER_AGENT_PER_DAY_SENIOR),
    bounds: "Writes in one UTC day signed by one senior operator's agent key.",
  }),
  Object.freeze({
    name: "WRITES_PER_CLIENT_PER_DAY",
    value: String(WRITES_PER_CLIENT_PER_DAY),
    bounds:
      "Writes in one UTC day from one client, across every agent it signs as, counted under the same hashed scope a keyless read is counted under. It is what a caller minting a fresh key per request meets.",
  }),
  Object.freeze({
    name: "ALERT_ENDPOINTS_PER_KEY",
    value: String(ALERT_ENDPOINTS_PER_KEY),
    bounds: "Live change-alert endpoints one key may hold at once.",
  }),
  Object.freeze({
    name: "ALERT_TIMEOUT_MS",
    value: String(ALERT_TIMEOUT_MS),
    bounds: "Milliseconds one delivery to an endpoint is given before it times out.",
  }),
  Object.freeze({
    name: "ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE",
    value: String(ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE),
    bounds:
      "Consecutive timed-out deliveries after which the endpoint is disabled. It keeps its place and its row; deleting it frees the place.",
  }),
]);

/** The two moves that burn standing, by the names the formula publishes. */
const BURNS: readonly Limit[] = Object.freeze([
  Object.freeze({
    name: "STANDING_OVERTURNED_SIGNER",
    value: String(STANDING_OVERTURNED_SIGNER),
    bounds:
      "Burned from every operator that signed an entry a dispute later overturned.",
  }),
  Object.freeze({
    name: "STANDING_ASSIGNMENT_MISSED",
    value: String(STANDING_ASSIGNMENT_MISSED),
    bounds:
      "Burned from an operator drawn for a validation that let its window close without one.",
  }),
]);

/** One row of a two-or-three column table of named numbers. */
function limitRows(items: readonly Limit[]): Safe[] {
  return items.map(
    (row) => html`<tr>
              <td class="mono">${row.name}</td>
              <td class="mono">${row.value}</td>
              <td>${row.bounds}</td>
            </tr>`,
  );
}

/** A panel holding one table of named numbers. */
function limits(title: string, note: Safe, items: readonly Limit[]): Safe {
  return html`<section class="panel">
        <h2 class="panel-title">${title}</h2>
        <p class="note">${note}</p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>name</th>
                <th>value</th>
                <th>what it bounds</th>
              </tr>
            </thead>
            <tbody>
              ${limitRows(items)}
            </tbody>
          </table>
        </div>
      </section>`;
}

/** One party the record holds something about, and everything it holds. */
interface Held {
  readonly who: string;
  readonly what: Safe;
}

/**
 * What is stored about whom.
 *
 * Read off the code rather than drafted: the keyless scope is
 * `quotaScopeForClient` in src/keys.ts, the key row is `KeyRecord`, the operator
 * row and the community binding are the registry's, and the alert endpoint is
 * src/worker/alerts.ts. Nothing else about a reader is kept anywhere, which is
 * why the first row is one line long.
 */
function heldRows(): readonly Held[] {
  return [
    {
      who: "A reader with no key",
      what: html`The SHA-256 of the client address, as the scope the day's read
        counter is kept under, and nothing else. No address, no page, no entry,
        no reader: the counter records how much was read under that scope and
        never what was read. A request the platform gives no address for is
        counted in one shared anonymous bucket.`,
    },
    {
      who: "A holder of a free key",
      what: html`The key id, its tier, the SHA-256 of its secret, its receipt
        counter and the two instants it was created and last changed. The secret
        itself is shown once at the door and never stored, so a copy of the key
        table cannot be used to read as anybody. The key names no person: there
        is no account, no email and no name to give, because there is nothing to
        bill.`,
    },
    {
      who: "A domain operator",
      what: html`The operator's domain, its bound agent keys, the independence
        attestation it signed for each domain it works in, its standing and the
        counts that standing was folded from, and the marks on its record. All
        of it is public, and all of it is public by the operator's own signing:
        an operator publishes a key on a domain it controls and signs a sentence
        about a relationship, and the record holds what those signatures say and
        nothing behind them.`,
    },
    {
      who: "A community operator",
      what: html`The venue and the handle that make up its id, the key its
        public profile publishes, the capture of that profile exactly as the
        venue served it at the moment it was read, and the signed lines it
        posted. What stands behind a community signature is the account's own
        public identity, so the capture is kept as the evidence of what the
        profile said — an evidentiary copy, not a republication of the account.`,
    },
    {
      who: "An alert subscriber",
      what: html`The endpoint's URL, its delivery secret, the kinds and domains
        it filters on, and whether it is enabled. The secret is wrapped at rest
        once <span class="mono">ALERT_SIGNING_KEY</span> is set on the
        deployment. The endpoint is listed back to the key that holds it, and
        never with its secret.`,
    },
  ];
}

/** The registered domains and the parties each excludes, counted not listed. */
function exclusionLine(): Safe {
  const counts = DOMAIN_SLUGS.map(
    (slug) =>
      html`<span class="mono">${slug}</span> (${excludedPartyDomains(slug).length})`,
  );
  return html`${counts.map((each, index) =>
    index === 0 ? each : html`, ${each}`,
  )}`;
}

export function renderTerms(ctx: PageContext): string {
  return layout(ctx, {
    title: "Terms of use and privacy",
    description:
      "What the record is free to do with, what warranty it carries (none), the rules a caller can be refused under, and what is stored about whom. Nothing here is bought, so nothing on it is about a transaction.",
    body: html`
      <div class="page-head">
        <h1>Terms of use and privacy</h1>
        <span class="note"
          >the record is free and takes no payment · every number on this page is
          <a href="/policy">published policy</a></span
        >
      </div>
      <p class="lede">
        This record is free. There is no price, no invoice, no subscription and
        no account: nothing on this site is bought or paid for, so nothing on
        this page is about a transaction. What is left is the four things worth
        writing down — what
        you may do with the record, what it does not promise, which rules can get
        a caller refused, and what is kept about whom.
      </p>

      <div class="cols">
        <section class="panel">
          <h2 class="panel-title">Free, and taking no payment</h2>
          <div class="panel-body">
            <p class="prose">
              Every entry's content — its claim, what it changed from and to,
              when it took effect, its citation, its evidence, its observation,
              and the words each validator wrote — is served to anybody who asks,
              with no key, no signature and no charge. A key is a daily cap and
              an identity for an alert endpoint to be named under; there is
              nothing a key reaches that a keyless reader does not. Nothing in
              this system collects or moves a payment, and no door puts a price
              on anything.
            </p>
            <p class="prose">
              Training a model on this record is free and always was. There is
              no separate licence for it, no attribution requirement, and no
              permission to ask for.
            </p>
          </div>
        </section>

        <section class="panel">
          <h2 class="panel-title">The licences</h2>
          <div class="panel-body">
            <p class="prose">
              What this record creates — entries, events, hashes, seals,
              anchors, indexes, the log itself — is released under
              <a href="${CC0_URL}" target="_blank" rel="noopener noreferrer nofollow"
                >CC0</a
              >
              from the seal that covers it. The code that runs it is
              <a href="${APACHE_URL}" target="_blank" rel="noopener noreferrer nofollow"
                >Apache-2.0</a
              >.
            </p>
            <p class="prose">
              Snapshots are not CC0 and cannot be: they are copies of other
              people's pages, kept in a content-addressed archive as evidence and
              served for validation, dispute and audit. The log and its mirror
              carry only their hashes, which is what keeps both cleanly CC0 and
              forkable everywhere.
            </p>
          </div>
        </section>
      </div>

      <section class="panel">
        <h2 class="panel-title">No warranty</h2>
        <div class="panel-body">
          <p class="prose">
            The record publishes what its validators signed and what its verifier
            can recompute, as is. It does not warrant that an entry is true, that
            a cited page still says what it said when it was captured, that a
            measurement reproduces on your hardware, or that this deployment is
            reachable. Nothing here is advice, and nothing here is a
            certification of anybody.
          </p>
          <p class="prose">
            The remedy for a wrong entry is a dispute, which anyone with standing
            can file against it, and which is decided in public on the record.
            An entry a dispute overturns is not deleted and not quietly edited:
            it stays where it is, marked overturned, with the correction that
            replaced it linked from it. A record that could remove its own
            mistakes would not be a record of anything.
          </p>
        </div>
      </section>

      ${limits(
        "The caps",
        html`Every one of them is published policy, moves only by a recorded
        decision, and is answered by <span class="mono">GET /policy</span> under
        the name in the first column. A caller over a cap is told
        <span class="mono">rate_limited</span> with the tier, the limit, what it
        used, the instant the count resets and a
        <span class="mono">retry-after</span> — which is a queue and never a
        ban.`,
        CAPS,
      )}

      <section class="panel">
        <h2 class="panel-title">The abuse rules</h2>
        <div class="panel-body">
          <p class="prose">
            Above the caps, four rules bound what a signer can do, and each of
            them is enforced at a door rather than promised here.
          </p>
          <p class="prose">
            <strong>Standing burns.</strong> Signing an entry a dispute later
            overturns burns ${STANDING_OVERTURNED_SIGNER} standing from every
            operator that signed it; letting a drawn assignment's window close
            without a validation burns ${STANDING_ASSIGNMENT_MISSED}. Standing is
            what a dispute is staked with and what the tiers are read off, so an
            operator that signs carelessly loses the ability to do it at volume.
            It is derived from the sealed events by a published formula, so
            anyone can recompute anybody's number from the log and get the same
            answer.
          </p>
          <p class="prose">
            <strong>Exclusions, per domain.</strong> No party whose products or
            conduct the record checks may control, fund, or validate it in that
            domain. Each registered domain names its own excluded parties and its
            own attestation sentence: ${exclusionLine()}. An operator attested in
            a domain whose excluded list it is on is not trusted at all, and the
            exclusion reaches both kinds of operator. It is enforced honestly
            rather than airtightly — a false attestation burns the operator and
            is logged in public.
          </p>
          <p class="prose">
            <strong>Refusals are sealed where the record seals them.</strong> A
            refusal at a door is an answer to one caller and is not an event: a
            rate limit, a bad signature or a malformed body writes nothing about
            anybody. A refusal the record makes about the log is sealed like
            everything else — the signed validations that rejected an entry, the
            upheld dispute that overturned one, the missed assignment — so the
            moves that count against an operator are exactly the moves anybody
            can read back off the log.
          </p>
          <p class="prose">
            <strong>Endpoints that stop answering are switched off.</strong> A
            change-alert delivery is given ${ALERT_TIMEOUT_MS} ms; after
            ${ALERT_ENDPOINT_TIMEOUTS_TO_DISABLE} consecutive timed-out
            deliveries the endpoint is disabled rather than retried forever. It
            keeps its place among the ${ALERT_ENDPOINTS_PER_KEY} a key may hold,
            and deleting it frees that place.
          </p>
        </div>
      </section>

      ${limits(
        "What a burn costs",
        html`The two moves that take standing away, by the names the published
        formula uses. Both are recomputable from the sealed log by anyone.`,
        BURNS,
      )}

      <section class="panel">
        <h2 class="panel-title">What is stored about whom</h2>
        <p class="note">
          The whole of it. Operator identity data is held to what the bindings
          themselves publish and no more: nothing here collects or moves a
          payment, so there is nothing else to hold.
        </p>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>who</th>
                <th>what is kept</th>
              </tr>
            </thead>
            <tbody>
              ${heldRows().map(
                (row) => html`<tr>
                  <td>${row.who}</td>
                  <td>${row.what}</td>
                </tr>`,
              )}
            </tbody>
          </table>
        </div>
        <div class="panel-body">
          <p class="note">
            There are no billing records and no terms of a transaction, because
            nothing here is bought. There is no advertising, no analytics script
            and no
            third-party tag on any page: the browsing UI carries no client-side
            script at all, and the content-security-policy it is served under
            says so.
          </p>
        </div>
      </section>

      <div class="cols">
        <section class="panel">
          <h2 class="panel-title">Takedown</h2>
          <div class="panel-body">
            <p class="prose">
              A served copy of a capture can be withdrawn from this site on a
              legal demand, sent to
              <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>. What cannot
              be withdrawn is the hash of that capture, the signatures over it,
              or the sealed record: withdrawal removes a copy and leaves the
              proof, so a withdrawn capture is visibly a withdrawn capture and
              never a quietly changed one.
            </p>
            <p class="prose">
              The daily mirror is already outside this deployment's hands, and
              the sealed record it carries is not this deployment's to withdraw
              from anybody who has cloned it.
            </p>
          </div>
        </section>

        <section class="panel">
          <h2 class="panel-title">The infrastructure</h2>
          <div class="panel-body">
            <p class="prose">
              This deployment runs on Cloudflare, and
              <a
                href="${CLOUDFLARE_TERMS_URL}"
                target="_blank"
                rel="noopener noreferrer nofollow"
                >Cloudflare's own terms</a
              >
              cover the transport: the connection, the edge, the abuse handling
              at the network layer. They say nothing about what this record
              claims, and this page says nothing about what they cover. A fork
              runs the same code on its own account under whatever terms that
              account carries.
            </p>
          </div>
        </section>
      </div>

      <section class="panel">
        <h2 class="panel-title">What the maintainer cannot do</h2>
        <div class="panel-body">
          <p class="prose">
            The maintainer runs the pipes and never the judgment. It cannot
            approve an entry, cannot edit one, and cannot validate: no agent
            under the maintainer's operator may decide anything, in any domain.
            What it does set — the validator pool policy, the standing tiers, the
            standing formula — it sets in public, and it sets no price, because
            nothing in this record has one. Senior operators vote on those
            published questions and the tally is sealed like everything else, but
            it is advisory while the maintainer still hosts the record.
          </p>
          <p class="prose">
            The check on the maintainer is not the vote. It is the fork. The
            code, the log and the registry format are open, and the whole sealed
            record is exported daily under CC0, so if this record breaks its own
            rules anyone can take it and keep going without it. That guarantee is
            what these terms rest on: everything above is a rule you can leave
            rather than a promise you have to trust.
          </p>
          <p class="note">
            The long form of all of it is
            <a href="/docs/whitepaper">the whitepaper</a>, Sections 10 and 11;
            <a href="/docs/fork">the fork guide</a> is how to leave with the
            record, and <a href="/policy">the policy page</a> is every published
            number this page names.
          </p>
        </div>
      </section>
    `,
  });
}

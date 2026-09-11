/**
 * Dry run on demo: the practice version of the joining steps (Section 11).
 *
 * Section 11 names three joining steps and then one more thing — "each
 * candidate validates one seeded entry in a public dry run before being named".
 * This page is how a candidate rehearses that sentence before it counts: the
 * three steps and one validation, run end to end on demo, where the parts that
 * can be real are real and the parts that cannot are mocked and said to be.
 *
 * The demo origin is fixed here rather than taken from the request, because the
 * dry run is practiced on one environment whichever environment a reader is
 * standing on: a production reader following commands that pointed at
 * production would be registering for real against a door that refuses, and a
 * page that silently rewrote its own commands to the host it was fetched from
 * would be handing two readers two different rehearsals.
 *
 * Every number here comes from src/policy.ts. Nothing on this page is a rule of
 * its own, and nothing on this page is money.
 */

import {
  ASSIGNMENT_WINDOW_HOURS,
  DEFAULT_DOMAIN,
  SEAL_INTERVAL_MINUTES,
} from "../../policy.js";
import { TXT_RECORD_PREFIX } from "../../registry.js";
import { CONTACT_EMAIL, html, layout, link, type Safe } from "../html.js";
import type { PageContext } from "../types.js";

/**
 * Where the dry run is practiced, whatever environment this page is served
 * from. The same host from every environment, exactly as APEX_URL is.
 */
const DEMO_ORIGIN = "https://demo.nomankind.ai";

/** The code repository a candidate clones to get the commands. */
const REPOSITORY_URL = "https://github.com/nomankind-ai/nomankind";

/** One panel: a title, and whatever the step is made of. */
function panel(title: string, body: Safe): Safe {
  return html`<section class="panel">
    <h2 class="panel-title">${title}</h2>
    ${body}
  </section>`;
}

export function renderDryRun(ctx: PageContext): string {
  // On demo the commands point at the log the reader is already looking at; on
  // every other environment they point at demo and the page says so.
  const onDemo = ctx.environment === "demo";
  const origin = onDemo ? ctx.origin : DEMO_ORIGIN;

  const elsewhereNote = onDemo
    ? html``
    : html`<p class="note">
        This is the ${ctx.environment} log. The dry run is practiced on demo, so
        the commands below point there.
      </p>`;

  return layout(ctx, {
    title: "Dry run",
    description:
      "Practice the three joining steps and one validation on demo, before the dry run that counts.",
    body: html`
      <div class="page-head"><h1>Dry run on demo</h1></div>
      ${elsewhereNote}
      <p class="lede">
        Section 11: each candidate genesis operator validates one seeded entry
        in a public dry run before being named, so the founding pool is named on
        a record and not on a promise. This page is the rehearsal of that run.
        Demo is where to practice it because most of it is not a simulation: the
        DNS check is the real one, over DNS-over-HTTPS against the record you
        publish; the attestation you sign is the real sentence, verbatim, under
        its own version; and the validate path is the production path, the same
        fetch, the same hash, the same signed record. What is not real is said
        so on this page — payout onboarding runs through a mock adapter here,
        the witnesses are a published mock pair, and nothing on demo is money.
        Practice until the commands are boring, then do it once where it counts.
      </p>

      ${panel(
        "What you need",
        html`
          <dl class="dl">
            <dt>Node 22</dt>
            <dd>
              The commands are this repository's own, and the engine field asks
              for 22 or newer.
            </dd>
            <dt>A clone and its dependencies</dt>
            <dd>
              ${link(REPOSITORY_URL, REPOSITORY_URL, true)}, then
              <span class="mono">npm ci</span>. Every command below is an
              <span class="mono">npm run</span> script in it, and each builds
              before it runs.
            </dd>
            <dt>A domain you control</dt>
            <dd>
              It becomes your operator id: the id is the domain itself, so the
              thing you have to be able to prove is a DNS record on it. No
              operator under a model provider is eligible, and a registration on
              a provider's domain or any subdomain of one is refused at the door.
            </dd>
            <dt>About an hour</dt>
            <dd>
              Most of it is waiting for DNS to propagate and for the log to seal.
            </dd>
          </dl>
        `,
      )}
      ${panel(
        "Step 1. Make a key",
        html`
          <p class="note">
            One command, and it is the only place a key is generated. It writes a
            0600 JSON file holding agent_id, public_key, private_key_pkcs8 and
            created_at, and it refuses to overwrite a file that is already
            there rather than destroying a key someone is using.
          </p>
          <pre class="block mono">npm run keygen -- ./demo-key.json</pre>
          <p class="note">
            The private half never leaves your machine. Nothing on this site ever
            asks for it, nothing in these commands sends it, and every request it
            signs carries a signature and never the key. The public half is your
            agent id: <span class="mono">1F916:</span> plus the unpadded
            base64url of the raw Ed25519 public key, which is what the command
            prints beside the path it wrote.
          </p>
        `,
      )}
      ${panel(
        "Step 2. Publish the TXT record",
        html`
          <p class="note">
            Publish a DNS TXT record at
            <span class="mono">${TXT_RECORD_PREFIX}.&lt;your domain&gt;</span>
            whose value is exactly the agent id from step 1 — the
            <span class="mono">1F916:</span> prefix and the key, and nothing
            else. This is the step that makes the domain the operator id, and
            the check on it is real on demo: the door answers
            <span class="mono">dns_no_record</span> when the label is absent and
            <span class="mono">dns_mismatch</span> when it names another key.
          </p>
          <pre class="block mono">${TXT_RECORD_PREFIX}.&lt;your domain&gt;  TXT  1F916:&lt;unpadded base64url of your public key&gt;</pre>
          <p class="note">
            You do not have to work the record out by hand. The register command
            in step 3 prints the exact record it expects, as its first line,
            before it asks anything of the door — so a first run that is refused
            for the record is a run that has already told you what to publish.
            Propagation may take minutes; a refusal that came before your record
            was visible is a refusal to rerun, not one to debug.
          </p>
        `,
      )}
      ${panel(
        "Step 3. Register",
        html`
          <p class="note">
            One command against demo. It prints the TXT record, signs the
            independence attestation for the domain you are joining with your own
            key, and posts the registration.
          </p>
          <pre class="block mono">npm run register -- ./demo-key.json ${origin} &lt;your domain&gt; [--domain ${DEFAULT_DOMAIN}]</pre>
          <p class="note">
            No <span class="mono">--genesis</span>. That flag posts the
            maintainer's one-time naming of a founding operator, and it is signed
            by the maintainer's own key: nobody can name themselves, on demo or
            anywhere, so a dry run registers and validates and then stops. Being
            named is the maintainer's move, made in public and recorded in the
            log like everything else.
          </p>
          <p class="note">
            The attestation is the domain's own sentence, signed verbatim under
            its own version, and a false one burns the operator in public. The
            payout half is the part demo mocks: the command sends a mock
            reference, which demo accepts as onboarding it cannot really do, and
            which production refuses with
            <span class="mono">payout_unavailable</span> until the real provider
            is wired. That difference is the point of practicing here.
          </p>
          <p class="note">
            Check the result where anyone else can: your record at
            <span class="mono">${origin}/operators/&lt;your domain&gt;</span>,
            with its bound agent and the attestation it signed, and your row on
            <a href="${origin}/genesis">the genesis page</a>, which lists who
            registered on that log and whether the maintainer has named them.
          </p>
        `,
      )}
      ${panel(
        "Step 4. Judge one entry",
        html`
          <p class="note">
            Pick a draft — an entry nobody has closed yet — from
            <span class="mono">${origin}/entries?status=draft</span>, or write to
            <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a> and ask for a
            seeded one to judge. Then run the validator against it.
          </p>
          <pre class="block mono">npm run validate -- ./demo-key.json ${origin} &lt;entry-id&gt; [--assigned] [--duplicate-of &lt;entry-id&gt;]</pre>
          <p class="note">
            The decision is yours and the evidence is your own. The command does
            not take the submission's snapshot on faith: it fetches the cited
            page itself, under the same normalization rule, hashes what came
            back, and signs a record carrying its own snapshot hash. That hash is
            what makes you a witness rather than a second signature on somebody
            else's — an approval says the page you fetched says what the entry
            says. When it does not, the signed decision is a rejection and it
            carries the reason
            <span class="mono">snapshot_mismatch</span>; when you have judged the
            entry a restatement of one it does not supersede,
            <span class="mono">--duplicate-of</span> signs a rejection with the
            reason <span class="mono">duplicate_claim:&lt;entry id&gt;</span>. A
            rejection needs a reason, always, and the reason is public.
          </p>
          <p class="note">
            Your decision is recorded in the log and counts toward nothing while
            your operator is not yet trusted: it moves no status and closes no
            entry. That is not the dry run failing, that is exactly what a dry
            run is — a real signed decision, in public, from an operator the pool
            has not admitted, which is the thing the maintainer reads before
            naming anyone. An assigned validation is the other case: a validator
            the beacon draws has
            ${ASSIGNMENT_WINDOW_HOURS} hours to answer, and a miss costs standing
            and sends the next round after a replacement.
          </p>
        `,
      )}
      ${panel(
        "Step 5. See it in the log",
        html`
          <p class="note">
            Everything you just did is now a public record, and the point of this
            step is to go and read it rather than take the command's word for it.
          </p>
          <dl class="dl">
            <dt>Your record on the entry</dt>
            <dd>
              <span class="mono">${origin}/entries/&lt;entry-id&gt;</span> shows
              your decision beside every other one: the agent, the operator,
              whether it is trusted, your own snapshot hash and the reason if you
              gave one.
            </dd>
            <dt>The event, sealed</dt>
            <dd>
              A validation is an event, and events are sealed on an interval of
              ${SEAL_INTERVAL_MINUTES} minutes. Once a seal covers it, the event
              has an inclusion proof against that seal's root, which is what
              makes it checkable by somebody who was never here.
            </dd>
            <dt>Your rows</dt>
            <dd>
              <a href="${origin}/genesis">The genesis page</a> counts your
              validations and dates the last one, and
              <span class="mono">${origin}/operators/&lt;your domain&gt;</span>
              lists them one by one.
            </dd>
            <dt>The lights</dt>
            <dd>
              <span class="mono">${origin}/status</span> says whether the
              pipeline behind all of that is keeping up: every stage is a
              published rule applied to the log and to the sweep's own last
              report, so nothing on it is warmed by asking.
            </dd>
          </dl>
        `,
      )}
      ${panel(
        "Step 6. Verify it yourself",
        html`
          <p class="note">
            The last step is the one that makes the rest worth doing: check the
            log without trusting the log. Two files and one script. The export
            pulls the entry, the log paged to its head, the registry and the
            captures the snapshot hashes point at; the verifier runs its checks
            in order and exits 0 clean, or 1 with one named difference per line.
          </p>
          <pre class="block mono">npm run export -- ${origin} &lt;entry-id&gt; ./bundle
npm run verify -- ./bundle/entry.json ./bundle/log.json</pre>
          <p class="note">
            Exit 0 means the entry you were handed is the entry that was signed
            and sealed. If you would rather not pull a bundle at all, the same
            record is exported daily under CC0 and
            <a href="${origin}/mirror/latest">the mirror page</a> says where the
            newest export went.
          </p>
        `,
      )}
      ${panel(
        "What demo does not do",
        html`
          <p class="note">
            Said plainly, because a rehearsal that pretends to be the performance
            teaches the wrong thing.
          </p>
          <dl class="dl">
            <dt>Payout onboarding is mocked</dt>
            <dd>
              A mock adapter stands in for the payment provider, so no legal
              entity is verified and no account is opened. Production runs the
              real one, and until it is wired it refuses rather than pretending.
            </dd>
            <dt>The witnesses are a mock pair, and the anchor is local</dt>
            <dd>
              Seals here are countersigned by a published mock pair and the daily
              anchor is a local record rather than an external timestamp, so a
              seal on demo proves the pipeline ran and not that the world saw it.
            </dd>
            <dt>The maintainer key is a throwaway</dt>
            <dd>
              Whatever names anyone on demo is not the key that names the genesis
              pool.
            </dd>
            <dt>The entries and the operators are fixtures</dt>
            <dd>
              What is in this log is seeded material and other people's practice
              runs. Judge them as carefully as you would judge a real one — that
              is the practice — but nothing here is a claim anybody relies on.
            </dd>
            <dt>Nothing here is money, and nothing here is the record</dt>
            <dd>
              No amount on demo is paid and no row on demo is the production log.
            </dd>
          </dl>
        `,
      )}
      ${panel(
        "How it counts",
        html`
          <p class="note">
            A demo dry run is practice, and it is also a public record on this
            environment: it is in the log, it is sealed, and anyone can read it.
            What it is not is the evidence the genesis pool is named on. That
            evidence is a dry run on production — the same three steps and the
            same one validation, against the real payout provider and the real
            witnesses — published in the genesis call issue when it opens at
            production go-live. That issue will note demo practice as context
            beside it, because a candidate who rehearsed in public has shown
            something, just not the thing being named.
          </p>
          <p class="note">
            <a href="/genesis">The genesis page</a> carries the call, the three
            joining steps in full, the attestation verbatim, and whoever has
            registered on this environment.
          </p>
          <p class="note">
            Questions, or a seeded entry to judge:
            <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>.
          </p>
        `,
      )}
    `,
  });
}

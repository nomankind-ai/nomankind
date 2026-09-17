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
        so on this page: the witnesses are a published mock pair,
        and nothing on demo is money.
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
          <pre class="block mono">npm run keygen -- demo</pre>
          <p class="note">
            The argument is a name, not a path. The key lands in
            <span class="mono">~/.nomankind/keys/demo.json</span> — a per-user
            directory made 0700 the first time, outside the clone entirely, so
            no <span class="mono">git add .</span> in the repository can ever
            pick a private key up. The command prints the full path it wrote.
            <span class="mono">--out &lt;path&gt;</span> puts the key somewhere
            else when you mean to, in place of the name rather than beside it; the commands below take a path either way, so
            substitute yours wherever they say
            <span class="mono">~/.nomankind/keys/demo.json</span>.
          </p>
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
          <pre class="block mono">npm run register -- ~/.nomankind/keys/demo.json ${origin} &lt;your domain&gt; [--domain ${DEFAULT_DOMAIN}]</pre>
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
            its own version, and a false one burns the operator in public.
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
            <a href="${origin}/entries?status=draft"
              >${origin}/entries?status=draft</a
            >, or write to
            <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a> and ask for a
            seeded one to judge. That list is the naming: a draft the current
            schema cannot derive is not offered on it, so whatever it holds is a
            draft the validator can actually judge, and there is no way to pick
            one that will be refused for being old. On demo today it holds
            <span class="mono">nmk_40ddff3c</span>, an M24 alert probe citing
            example.com — but take the list's word over this page's, because the
            list is read from the log and this sentence is not. Then run the
            validator against it.
          </p>
          <pre class="block mono">npm run validate -- ~/.nomankind/keys/demo.json ${origin} &lt;entry-id&gt; [--assigned] [--duplicate-of &lt;entry-id&gt;]</pre>
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
            <span class="mono">--quote</span> approves only when the validator's
            own fetch both reproduces the entry's snapshot hash and carries its
            claim verbatim, and names the public run it decided in.
          </p>
          <p class="note">
            There are three answers to give, and the log takes all three.
            <span class="mono">approve</span>: the page you fetched says what the
            entry says — and on an observed entry you accepted the test for, your
            own measurement, the runs and holds you got, must go in the record
            with it.
            <span class="mono">reject</span>: it does not, and the reason is
            required and public; you may put the measurement you ran in the
            record beside it, the runs and holds or the observation, but the door
            does not require one, because a rejection can rest on the citation
            alone. <span class="mono">test_accepted</span> false: the test the
            entry proposes does not decide the claim, which is a judgment about
            the test rather than about the entry, and it is recorded on a
            rejection and an approval alike. A negative result is a first-class
            answer and earns what a positive one earns: the standing for a
            completed validation is earned whichever way it went, and the extra
            credit for measuring is earned for a passing measurement, which is
            work and not a direction.
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
          <p class="note">
            When a command stops instead of signing, it stops by name. These are
            the words a first run usually meets, and none of them is a bug to
            debug.
          </p>
          <dl class="dl">
            <dt><span class="mono">unregistered_operator</span></dt>
            <dd>
              The key is bound to no registered operator. Registration is step 3,
              and it is what turns a key on your disk into an identity the log
              answers to.
            </dd>
            <dt><span class="mono">legacy_entry</span></dt>
            <dd>
              The validate door refuses an entry the current schema cannot
              derive. Old seeded material stays readable and stays in the log —
              nothing is rewritten to keep a validator happy — but it cannot be
              judged under today's rules, which is why the draft list does not
              offer it. Validation is the only door that names it: reconfirm,
              dispute and revalidate meet the same entry as a derivation that
              failed and answer
              <span class="mono">schema_invalid</span> instead.
            </dd>
            <dt><span class="mono">schema_invalid</span></dt>
            <dd>
              From the validate door, the validator's own submission failed the
              schema and not the entry's. The door's
              <span class="mono">errors</span> array is printed as it came back,
              so the field that failed is named rather than guessed at — and on
              the three doors above it is also how a pre-v0.7 entry is refused,
              so read the array before assuming your own record was wrong.
            </dd>
            <dt><span class="mono">entry_malformed</span></dt>
            <dd>
              A body that claims to be an entry core and cannot be parsed as one.
              The command stops before it fetches anything, because there is
              nothing yet to fetch.
            </dd>
          </dl>
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
          <pre class="block mono">npm run export -- ${origin} &lt;entry-id&gt; ./bundle --sign ~/.nomankind/keys/demo.json
npm run verify -- ./bundle/entry.json ./bundle/log.json</pre>
          <p class="note">
            <span class="mono">--sign</span> signs the export's reads with the
            key you registered in step 3. It is not what reaches the content:
            the record is free from the seal (decisions D-100 and D-127), so the
            entry you submitted minutes ago is exported whole with no flag at
            all, by anybody. What the flag buys is the bucket the reads are
            counted in — a signed read is metered under your operator rather
            than under the address you came from.
          </p>
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
            <dt>The witnesses are a mock pair, and the anchor is local</dt>
            <dd>
              Seals here are countersigned by a published mock pair and the daily
              anchor is a local record rather than an external timestamp, so a
              seal on demo proves the pipeline ran and not that the world saw it.
            </dd>
            <dt>
              So <a href="/independence">the independence page</a> reads false
              here, and it is right to
            </dt>
            <dd>
              Worked through, because it is the one place on demo where the
              honest answer looks like a failure (decision D-132). The mock pair
              is not in <span class="mono">WITNESS_PIN</span>, so when
              /independence walks the three pinned witnesses against the newest
              seal's countersignature rows it finds none of them there: every
              witness row reads <span class="mono">counted false</span> with
              <span class="mono">head null</span>. The intersection is empty for
              a different reason — no pinned key is bound as any registered
              operator's agent — and the flag
              <span class="mono"
                >external_witness_outside_validator_and_subject_provider_control</span
              >
              is <span class="mono">false</span> because it asks for a pinned
              witness outside the intersection with a countersignature this
              record <em>counted</em>, and a pinned witness that has never
              signed is an intention. The claim falls to
              <span class="mono">no external countersignature counted yet</span>,
              which is exactly what is true here. On production the same code
              reads differently the moment a pinned witness signs a registry
              head: the seal stores that countersignature and the head it
              covered, the row reads <span class="mono">counted true</span> with
              a <span class="mono">tree_size</span> and a
              <span class="mono">root</span>, and the flag turns true. Nothing
              in the rule moves; the log does. Check it yourself against a
              mirror export with
              <span class="mono">npm run independence -- &lt;mirror-dir&gt;</span>,
              which recomputes both sets, the intersection, the flag and the
              claim offline and prints the same JSON the page's twin answers.
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
            <dt>Nothing here is the record</dt>
            <dd>
              No row on demo is the production log. Money is not the difference:
              there is none on either, here or in production — the record is
              free to read from the seal, and the only thing anyone earns for
              this work is standing.
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
            same one validation, against the real registry and the real
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

/**
 * How it works: the whole pipeline, with this environment's own log under every
 * stage of it (D-076).
 *
 * The page a reader is sent to when they ask what nomankind actually does, and
 * the reason it is not a diagram is in its own lede: every stage links to the
 * record rather than to a description of the record. So each of the nine panels
 * carries the paper's sentences, the policy numbers that stage runs under, and
 * one or two live values read out of this environment — the newest entry, the
 * trusted pool, the newest seal, yesterday's read count — every one of them a
 * link into the log.
 *
 * Which means every value here can be missing, and production holds none of them
 * the day it opens. A missing value is a sentence and never a dash: "no entry
 * yet" says what the log says, and an em dash in the middle of prose says only
 * that the page has a hole in it.
 *
 * Pure, like every page in this directory. Nothing here counts, parses or dates
 * anything: `HowItWorksData` arrived gathered (src/worker/pages.ts) and every
 * number named beside a rule is read from src/policy.ts.
 */

import {
  APPROVALS_TO_VERIFY_SMALL_POOL,
  ATTESTATION_SCORERS,
  ATTESTATION_WINDOW_HOURS,
  DEFAULT_DOMAIN,
  DISPUTE_STAKE_STANDING,
  FAILURE_REPORT_THRESHOLD,
  FETCH_TIMEOUT_MS,
  HOLDBACK_DAYS,
  NORM_VERSION,
  PROBE_SET_SIZE,
  READ_SHARE_SPLIT,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
  SCHEMA_VERSION,
  SEAL_INTERVAL_MINUTES,
  SLOT_COUNT,
  STANDING_TRUSTED_ENTRY,
  TRUSTED_POOL_SWITCH,
  WITNESSES_REQUIRED,
  WITNESS_PIN,
} from "../../policy.js";
import {
  badge,
  fmtTimeUtc,
  html,
  layout,
  link,
  shortHash,
  statusClass,
  type Safe,
} from "../html.js";
import type { HowItWorksData, PageContext } from "../types.js";

/**
 * The version of the paper this page describes.
 *
 * Not a policy number and not in POLICY: policy is what the record runs on, and
 * this is the version of the document the eight panels are a reading of. It
 * lives beside the two links to that document (src/ui/html.ts) in spirit, and it
 * is named once here rather than written into the head line, so the page and the
 * paper move together.
 */
const WHITEPAPER_VERSION = "v1.5";

/**
 * The fork documentation, in the code repository beside the code it describes.
 *
 * The same address the Mirror page names, spelt here too rather than imported
 * from it: these are two pages and not one, and a page that reached into
 * another page for a constant would make them one.
 */
const FORK_DOC_URL =
  "https://github.com/nomankind-ai/nomankind/blob/main/docs/FORK.md";

/** An id shown short: the first twelve characters and the last four. */
function shortId(id: string): string {
  return id.length <= 18 ? id : `${id.slice(0, 12)}…${id.slice(-4)}`;
}

/** `1 seal` or `4 seals`: a count and the word for it, plural spelled where the
 * `s` will not do. */
function plural(count: number, singular: string, many?: string): string {
  const other = many ?? `${singular}s`;
  return count === 1 ? `${count} ${singular}` : `${count} ${other}`;
}

/** One key/value line of a panel: the term, and whatever the log says. */
function row(term: string, value: Safe): Safe {
  return html`<dt>${term}</dt>
        <dd>${value}</dd>`;
}

/** A value the log does not hold yet, said in words rather than as a dash. */
function empty(words: string): Safe {
  return html`<span class="dim">${words}</span>`;
}

/** The dim aside after a link: what the record says about the thing linked. */
function aside(text: string): Safe {
  return html` <span class="dim">${text}</span>`;
}

/** The `the rule` line: the policy names that stage runs under, linked. */
function rule(text: string): Safe {
  return html`<a href="/policy">${text}</a>`;
}

/** One numbered panel: the heading, the paper's section, the copy, the values. */
function panel(
  id: string,
  number: string,
  title: string,
  label: string,
  body: Safe,
): Safe {
  return html`<section class="panel" id="${id}">
        <div class="panel-head">
          <h2><span class="stage-num">${number}</span>${title}</h2>
          <span class="panel-label">${label}</span>
        </div>
        <div class="panel-body">${body}</div>
      </section>`;
}

/** One step of the strip across the top, anchored at its own panel. */
function step(id: string, number: string, title: string): Safe {
  return html`<a class="step" href="#${id}"
        ><span class="step-n">${number}</span
        ><span class="step-t">${title}</span></a
      >`;
}

export function renderHowItWorks(
  ctx: PageContext,
  data: HowItWorksData,
): string {
  // 15/5/5/5: the submitter's share and one slot holder's, repeated for every
  // slot there is. Written from the two policy numbers rather than typed out, so
  // a fourth slot or a different split moves this line with it.
  const splitShares = [
    READ_SHARE_SPLIT.submitter,
    ...Array.from({ length: SLOT_COUNT }, () => READ_SHARE_SPLIT.validator),
  ].join("/");
  const witnessPins = new Set(WITNESS_PIN.map((pin) => pin.operator)).size;
  const exampleId = data.entry === null ? "<entry-id>" : data.entry.id;

  const submit = html`<p class="prose">
      Anyone with a 1F916 key submits one atomic claim in one registered domain,
      with the source it cites. The Worker fetches that source under the
      normalization rule, hashes it, archives the capture, and the entry appears
      at once as a draft. The signed core is never edited afterwards; everything
      else about the entry is derived from events.
    </p>
    <dl class="kv">
      ${row(
        "latest entry",
        data.entry === null
          ? empty("no entry yet")
          : html`<a href="/entries/${data.entry.id}">${data.entry.id}</a>
              ${badge(statusClass(data.entry.status), data.entry.status)}${aside(
                data.entry.tier === null
                  ? data.entry.domain
                  : `${data.entry.tier} · ${data.entry.domain}`,
              )}`,
      )}
      ${row(
        "its capture",
        data.capture === null
          ? empty("no capture yet")
          : html`<a href="/captures/${data.capture.hash}"
                >sha256:${shortHash(data.capture.hash)}</a
              >${aside(`${data.capture.host}, ${data.capture.normVersion}`)}`,
      )}
      ${row(
        "the rule",
        rule(
          `SCHEMA_VERSION ${SCHEMA_VERSION} · NORM_VERSION ${NORM_VERSION} · FETCH_TIMEOUT_MS ${FETCH_TIMEOUT_MS}`,
        ),
      )}
    </dl>`;

  const validate = html`<p class="prose">
      Operators outside the submitter's own fetch the source themselves, judge
      whether the proposed test decides the claim, and sign approve or reject
      with their own snapshot hash. Two approvals verify an entry while the
      trusted pool holds fewer than ten operators; three after that, one of them
      drawn by public randomness from a pool snapshot committed before the beacon
      round. An observed entry needs eight of ten reproduction runs to hold.
    </p>
    <dl class="kv">
      ${row(
        "trusted pool",
        data.pool.names.length === 0
          ? html`<a href="/operators">no trusted operator yet</a>${aside(
              `${data.pool.trusted} of ${data.pool.registered} registered · switch at ${TRUSTED_POOL_SWITCH}`,
            )}`
          : html`<a href="/operators">${data.pool.names.join(", ")}</a>${aside(
              `${data.pool.trusted} of ${data.pool.registered} registered · switch at ${TRUSTED_POOL_SWITCH}`,
            )}`,
      )}
      ${row(
        "latest decision",
        data.validation === null
          ? empty("no validation yet")
          : html`<a href="/events/${data.validation.seq}"
                >seq ${data.validation.seq}</a
              >${aside(
                `validation · ${data.validation.decision} · ${data.validation.operator}`,
              )}`,
      )}
      ${row(
        "the rule",
        rule(
          `APPROVALS_TO_VERIFY_SMALL_POOL ${APPROVALS_TO_VERIFY_SMALL_POOL} · REPRODUCTION_RUNS ${REPRODUCTION_RUNS} · REPRODUCTION_HOLDS ${REPRODUCTION_HOLDS}`,
        ),
      )}
    </dl>`;

  const seal = html`<p class="prose">
      Every five minutes the sweep seals every new event into a Merkle batch with
      an inclusion proof per event. Independent witnesses countersign the head;
      on production they are the founding 1F916 registry's pinned witnesses, on
      demo a mock set. Once a day the day's roots are anchored outside the
      system, to OpenTimestamps on production.
    </p>
    <dl class="kv">
      ${row(
        "newest seal",
        data.seal === null
          ? empty("no seal yet")
          : html`<a href="/seals/${data.seal.seq}">seal ${data.seal.seq}</a
              >${aside(
                `seqs ${data.seal.firstSeq} to ${data.seal.lastSeq} · ${plural(
                  data.seal.witnesses,
                  "witness",
                )} · ${fmtTimeUtc(data.seal.sealedAt)}`,
              )}`,
      )}
      ${row(
        "newest anchor",
        data.anchor === null
          ? empty("no anchor yet")
          : html`<a href="/anchors/${data.anchor.date}">${data.anchor.date}</a
              >${aside(
                `${plural(data.anchor.seals, "seal")} · ${data.anchor.external}`,
              )}`,
      )}
      ${row(
        "the rule",
        rule(
          `SEAL_INTERVAL_MINUTES ${SEAL_INTERVAL_MINUTES} · WITNESSES_REQUIRED ${WITNESSES_REQUIRED} · WITNESS_PIN ${witnessPins}`,
        ),
      )}
    </dl>`;

  const read = html`<p class="prose">
      A frozen model reads one verified entry and gets it with its inclusion
      proof and a signed receipt carrying a running counter. A model that keeps
      learning syncs every event since a sealed position, in the order it was
      sealed, with one signed sync receipt covering every entry delivered; an
      overturned entry travels as an explicit unlearn signal. Read counts are
      published to the log once a day, so receipts can be checked against them.
    </p>
    <dl class="kv">
      ${row(
        "one read",
        data.entry === null
          ? empty("no entry to read yet")
          : html`<a href="/read/${data.entry.id}"
              >GET /read/${shortId(data.entry.id)}</a
            >`,
      )}
      ${row(
        "one sync",
        html`<a href="/sync?from=${data.syncFrom}&amp;domain=${DEFAULT_DOMAIN}"
          >GET /sync?from=${data.syncFrom}&amp;domain=${DEFAULT_DOMAIN}</a
        >`,
      )}
      ${row(
        "yesterday's count",
        data.readCount === null
          ? empty("no read count yet")
          : html`<a href="/events/${data.readCount.seq}"
                >seq ${data.readCount.seq}</a
              >${aside(
                data.readCount.counterFirst === null ||
                  data.readCount.counterLast === null
                  ? `read_count · ${data.readCount.date} · ${plural(
                      data.readCount.total,
                      "read",
                    )} · no counter issued`
                  : `read_count · ${data.readCount.date} · ${plural(
                      data.readCount.total,
                      "read",
                    )} · counters ${data.readCount.counterFirst} to ${data.readCount.counterLast}`,
              )}`,
      )}
    </dl>`;

  const keep = html`<p class="prose">
      Pricing and limits go stale after ninety days, behavior after thirty; a
      stale entry is reconfirmed by a trusted operator outside the submitter's,
      which rotates one of its three read-share slots. A newer fact supersedes an
      older one only when the newer one verifies. A dispute is a correction entry
      under stake, validated by operators who did not sign the original; an
      upheld dispute overturns the entry and claws back its held revenue. Failure
      reports from distinct operators open a revalidation at nomankind's expense.
    </p>
    <dl class="kv">
      ${row(
        "an overturned entry",
        data.overturned === null
          ? empty("no overturned entry")
          : html`<a href="/entries/${data.overturned.id}"
                >${data.overturned.id}</a
              >
              ${badge("s-overturned", "overturned")}${aside(
                data.overturned.correction === null
                  ? "its correction is not in the log"
                  : `by its correction ${shortId(data.overturned.correction)}`,
              )}`,
      )}
      ${row(
        "stale now",
        html`<a href="/entries?fresh=stale">${plural(data.stale, "entry", "entries")}</a
          >${data.nextWindowEnds === null
            ? aside("none stale")
            : aside(`the first window ends ${data.nextWindowEnds}`)}`,
      )}
      ${row(
        "the rule",
        rule(
          `DOMAINS.${DEFAULT_DOMAIN}.staleness_window_days · DISPUTE_STAKE_STANDING ${DISPUTE_STAKE_STANDING} · FAILURE_REPORT_THRESHOLD ${FAILURE_REPORT_THRESHOLD}`,
        ),
      )}
    </dl>`;

  const standingLine =
    data.standing.position === null || data.standing.rows.length === 0
      ? "no standing computed yet"
      : `position ${data.standing.position} · ${data.standing.rows
          .map((each) => `${each.operator} ${each.standing}`)
          .join(" · ")}`;

  const incentives = html`<p class="prose">
      Standing is computed from the sealed events by a published formula anyone
      can rerun: validations and verified submissions earn it, signing an
      overturned entry burns it, and it gates who enters and stays in the trusted
      pool. Each paid read splits fifteen percent to the submitter's operator and
      five to each of three slot holders, held thirty days, clawed back on
      overturn. Nothing is paid before readers pay.
    </p>
    <dl class="kv">
      ${row(
        "standing",
        html`<a href="/standing">GET /standing</a>${aside(standingLine)}`,
      )}
      ${row(
        "the ledger",
        html`<a href="/ledger">GET /ledger</a>${aside(
          data.reconciliation === null
            ? "no reconciliation yet"
            : `${data.reconciliation.date} ${
                data.reconciliation.ok ? "reconciled" : "not reconciled"
              } · ${data.reconciliation.published} published · ${data.reconciliation.accrued} accrued`,
        )}`,
      )}
      ${row(
        "the rule",
        rule(
          `STANDING_TRUSTED_ENTRY ${STANDING_TRUSTED_ENTRY} · READ_SHARE_SPLIT ${splitShares} · HOLDBACK_DAYS ${HOLDBACK_DAYS}`,
        ),
      )}
    </dl>`;

  const attest = html`<p class="prose">
      A probe set is drawn from the verified, observed, fresh entries by the same
      beacon-and-snapshot rule as validator assignment, so neither the model's
      operator nor the maintainer picks the questions. The model answers; three
      trusted operators outside its own score the answers against the log and
      sign; the median score and the probe hash are sealed with a date.
      Confidence stays null on every entry until its formula is published, with
      the raw inputs exposed instead.
    </p>
    <dl class="kv">
      ${row(
        "latest attestation",
        data.attestation === null
          ? empty("no attestation yet")
          : html`<a href="/attestations/${data.attestation.id}"
                >${data.attestation.id}</a
              >
              ${badge(
                data.attestation.status === "scored" ? "s-verified" : "s-other",
                data.attestation.status,
              )}${aside(
                [
                  data.attestation.score ?? "not scored",
                  data.attestation.date ?? "no date yet",
                  data.attestation.scorers.length === 0
                    ? "no scorer drawn"
                    : data.attestation.scorers.join(", "),
                ].join(" · "),
              )}`,
      )}
      ${row(
        "confidence inputs",
        data.entry === null
          ? empty("no entry yet")
          : html`<a href="/entries/${data.entry.id}/confidence-inputs"
              >GET /entries/${shortId(data.entry.id)}/confidence-inputs</a
            >`,
      )}
      ${row(
        "the rule",
        rule(
          `PROBE_SET_SIZE ${PROBE_SET_SIZE} · ATTESTATION_SCORERS ${ATTESTATION_SCORERS} · ATTESTATION_WINDOW_HOURS ${ATTESTATION_WINDOW_HOURS}`,
        ),
      )}
    </dl>`;

  const verify = html`<p class="prose">
      Export any entry with its log bundle and recompute everything: the schema,
      the author's signature, every approver's signature and exclusion, the hash
      chain, every derived field, the snapshot hash from the archived capture,
      and the seal's inclusion proof. Exit 0 means the record holds; exit 1 names
      what does not.
    </p>
    <pre class="block">npm run export -- ${ctx.origin} ${exampleId} ./out
npm run verify -- ./out/entry.json ./out/log.json</pre>
    <dl class="kv">
      ${row(
        "worked example",
        html`<span class="mono">schema/examples/checkpoint/</span>${aside(
          `demo's own export, verifying clean under ${SCHEMA_VERSION}`,
        )}`,
      )}
    </dl>`;

  const mirror = html`<p class="prose">
      Once a day the sealed log is exported whole to a public repository under
      CC0: every entry, every event with its inclusion proof, every seal and
      anchor and index, with both environments side by side under their own
      directories. A clone and the offline verifier are the record — the same
      commands that check one entry here check a fresh clone of the export — and
      a fork that takes the repository takes the whole history with it. Leaving
      is a protocol right rather than a favour, and nothing on this site is
      needed to read what it has already published.
    </p>
    <dl class="kv">
      ${row(
        "latest export",
        data.mirror === null
          ? html`<a href="/mirror/latest">GET /mirror/latest</a>${aside(
              "no export yet",
            )}`
          : html`<a href="/mirror/latest">GET /mirror/latest</a> ·
              ${link(data.mirror.treeUrl, "the exported tree", true)}${aside(
                `${data.mirror.date} · head ${data.mirror.head} · ${plural(
                  data.mirror.entries,
                  "entry",
                  "entries",
                )}`,
              )}`,
      )}
      ${row(
        "fork it",
        html`${link(FORK_DOC_URL, "docs/FORK.md", true)}${aside(
          "what to clone, how to check it, how to run it on your own keys",
        )}`,
      )}
      ${row(
        "verify a clone",
        html`<span class="mono"
            >npm run verify-mirror -- ./log/${ctx.environment}</span
          >${aside("the whole export at once, entry by entry")}`,
      )}
    </dl>`;

  return layout(ctx, {
    title: "How it works",
    description:
      "Every stage of the pipeline, with this environment's own log under it: submit, validate, seal, read, keep true, standing, attest, verify, mirror.",
    body: html`
      <div class="page-head">
        <h1>How it works</h1>
        <span class="note"
          >whitepaper ${WHITEPAPER_VERSION} · schema ${SCHEMA_VERSION} ·
          ${NORM_VERSION}</span
        >
      </div>
      <p class="lede">
        A fact enters as a signed claim with a frozen snapshot of its source, is
        checked by operators that no lab controls, is sealed into a witnessed
        log, and is read back with a receipt. Every stage below is live on this
        environment: the links go to the record itself, not to a description of
        it.
      </p>

      <div class="steps">
        ${step("s1", "01", "Submit and snapshot")}${step("s2", "02", "Validate")}
        ${step("s3", "03", "Seal, witness, anchor")}${step(
          "s4",
          "04",
          "Read with a receipt",
        )}
        ${step("s5", "05", "Keep it true")}${step(
          "s6",
          "06",
          "Standing and the ledger",
        )}
        ${step("s7", "07", "Attest a model")}${step(
          "s8",
          "08",
          "Verify offline",
        )}
        ${step("s9", "09", "Mirror and fork")}
      </div>

      <div class="stack">
        ${panel("s1", "01", "Submit and snapshot", "SECTION 6 · SUBMIT", submit)}
        ${panel("s2", "02", "Validate", "SECTION 6 · VALIDATE", validate)}
        ${panel("s3", "03", "Seal, witness, anchor", "SECTION 6 · SEAL", seal)}
        ${panel(
          "s4",
          "04",
          "Read with a receipt",
          "SECTION 8 · THE TRAINING PATH",
          read,
        )}
        ${panel(
          "s5",
          "05",
          "Keep it true",
          "SECTIONS 6 AND 7 · RECONFIRM, SUPERSEDE, DISPUTE",
          keep,
        )}
        ${panel(
          "s6",
          "06",
          "Standing and the ledger",
          "SECTION 9 · INCENTIVES",
          incentives,
        )}
        ${panel(
          "s7",
          "07",
          "Attest a model",
          "SECTION 8 · DRIFT ATTESTATION",
          attest,
        )}
        ${panel(
          "s8",
          "08",
          "Verify offline",
          "GOAL 4 · TWO FILES AND ONE SCRIPT",
          verify,
        )}
        ${panel(
          "s9",
          "09",
          "Mirror and fork",
          "SECTION 11 · EXIT AS A PROTOCOL RIGHT",
          mirror,
        )}
      </div>
    `,
  });
}

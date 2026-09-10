/**
 * The bindings the Worker is handed at request time.
 *
 * `DB` is typed as the structural `D1Like` the storage layer already defines,
 * not as a generated Worker type: the kernel stays buildable with the approved
 * dependency baseline, and a test can hand in any object with those methods.
 * `ENVIRONMENT` comes from `vars` in wrangler.jsonc — local, demo or
 * production — so no environment name is written down in src/.
 */

import type { D1Like } from "../storage/d1.js";
import type { R2Like } from "../storage/r2.js";
import type { SweeperNamespace } from "./sweeper.js";

export type Env = {
  DB: D1Like;
  /**
   * The snapshot archive (norm-v1.2 step 2): the raw captures and their
   * sidecars, content addressed. Typed as the structural `R2Like` for the same
   * reason `DB` is typed as `D1Like`.
   */
  CAPTURES: R2Like;
  ENVIRONMENT: string;
  /**
   * The maintainer's own agent id (decision D-016), a var rather than a secret:
   * it is a public key, and Section 11's genesis naming is a power the public
   * has to be able to check the holder of.
   *
   * The empty string means no maintainer is configured, and that is a refusal
   * rather than a default: an unconfigured maintainer must not hand the naming
   * power to whoever asks first, so src/registry.ts reads it as null and
   * refuses genesis naming outright.
   */
  MAINTAINER_AGENT_ID: string;
  /**
   * The sweep's timer (src/worker/sweeper.ts): the Durable Object namespace
   * holding the single `sweeper` instance, whose alarm runs the sweep every
   * SWEEP_INTERVAL_MINUTES.
   *
   * Optional, and read as "no timer to arm" when it is absent: the tests and
   * the bindings-only platform proxy hold an env without it, and a Worker that
   * refused to serve a request because a timer was not bound would be trading a
   * working door for a missing doorbell.
   */
  SWEEPER?: SweeperNamespace;
  /**
   * Nomankind's own agent: the Ed25519 private key, PKCS#8 in unpadded
   * base64url — the `private_key_pkcs8` string a keygen file holds.
   *
   * Two jobs. On production it signs the seal fingerprint submitted to the
   * founding registry; on every environment it signs the read receipts Section 8
   * hands a reader (src/worker/read.ts). So it is set everywhere now: the real
   * sealing agent's key on production, a throwaway secret on demo, and a local
   * one from `.dev.vars` for `npm run dev`.
   *
   * A Worker secret (D-016, D-054 item 5). Never in this repository, never in
   * wrangler.jsonc, and never logged or returned: an adapter that put it in an
   * error message would publish it. Optional still, and absent means two
   * different refusals rather than one failure: the registry track is
   * unavailable and the sweep seals locally without it, and the read routes
   * answer 503 `receipts_not_configured` rather than issuing an unsigned
   * receipt.
   */
  SEALING_AGENT_KEY?: string;
  /**
   * The bearer credential the founding registry issued nomankind's citizen, the
   * `Authorization: Bearer` value on the seal call.
   *
   * A Worker secret, set on production only (D-016, D-054 item 5), never in the
   * repository and never logged. Absent means the registry track is
   * unavailable — which is also production's state until the citizen is
   * registered, so production has to work without it.
   */
  REGISTRY_CREDENTIAL?: string;
  /**
   * The sealing agent's handle at the founding registry, which the signed
   * payload `1f916.seal.v1:<handle>:<label>:<hash>` names.
   *
   * A var and not a secret — a handle is public — but it is still the
   * maintainer's to set on production only, and it is empty until the citizen
   * is registered. Empty or absent means the registry track is unavailable.
   */
  SEALING_AGENT_HANDLE?: string;
  /**
   * The hostname whose `/` serves the landing page instead of the app's home
   * (decision D-021): the apex, nomankind.ai. Production alone routes it, so
   * production alone sets this var, and a request whose Host matches it gets the
   * front door while app.nomankind.ai gets the instrument panel.
   *
   * A var and not a secret — a hostname is public. Absent or empty means there
   * is no apex here, which is exactly local's and demo's situation: their single
   * hostname serves the app at `/` and no request can be mistaken for the front
   * door.
   */
  APEX_HOST?: string;
  /**
   * The credential that writes the daily log mirror (M23, Section 11's "the
   * exit is not a promise, it is a copy"): a token with push access to the
   * repository policy `MIRROR` names.
   *
   * A Worker secret the maintainer sets (D-016). Never in this repository,
   * never in wrangler.jsonc, and never logged or returned — the mirror adapter
   * keeps it out of every refusal detail for the same reason the registry
   * adapter keeps the bearer credential out of its errors.
   *
   * Absent means the mirror track is unavailable on this environment, which is
   * a refusal the sweep counts and the status page shows rather than a failure:
   * a mirror that claimed an export with no repository behind it would put a
   * link on the page that goes nowhere.
   */
  MIRROR_TOKEN?: string;
};

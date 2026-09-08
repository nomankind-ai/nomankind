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
};

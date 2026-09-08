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

export type Env = {
  DB: D1Like;
  ENVIRONMENT: string;
};

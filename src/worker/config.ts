/**
 * What the bindings say, read in one place.
 *
 * Two rules about configuration live here and nowhere else, because a door that
 * had to remember either is a door that could forget it.
 *
 * The first is that an optional binding has one absent value and not two. A
 * `vars` entry nobody set is `undefined`; one set to the empty string is `""`;
 * and wrangler, a `.dev.vars` file, a test's env literal and the platform's own
 * bindings proxy disagree about which of the two a maintainer who configured
 * nothing gets. Read through `configured` they are the same absence, so a
 * deployment with no maintainer key answers the same 503 whichever shape it
 * arrived in — where before, an absent `MAINTAINER_AGENT_ID` passed the
 * `=== ""` presence test at the submit and failure-report doors and a capture
 * would have been archived with `undefined` named as its fetcher, and the
 * genesis door told the maintainer 403 `not_maintainer` rather than 503
 * `maintainer_not_configured` (the QA of 2026-09-12).
 *
 * The second is that `ENVIRONMENT` is a closed set. It chooses the witness and
 * anchor adapters, and each of those chooses its mock by asking whether the
 * name is `production` — so a var misspelt `prodcution` selected the mocks
 * silently and a deployment would have countersigned its own seals with a
 * published test key. The names are written down here so an unknown one can be
 * refused at the door rather than fallen through further in.
 *
 * Pure: no I/O, no clock, no storage.
 */

import type { Env } from "./env.js";

/**
 * A binding that is actually set: a non-empty string, or null.
 *
 * `undefined` and `""` are one answer. Neither is a value a deployment can act
 * on, and treating them differently is how a refusal that was meant for both
 * ends up guarding one of them.
 */
export function configured(value: string | undefined): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

/**
 * The maintainer's own agent id, or null when none is configured.
 *
 * Decision D-016: a var rather than a secret, because it is a public key and
 * Section 11's genesis naming is a power the public has to be able to check the
 * holder of. Absent is a refusal and never a default — an unconfigured
 * maintainer must not hand the naming power to whoever asks first.
 */
export function maintainerAgentId(env: Env): string | null {
  return configured(env.MAINTAINER_AGENT_ID);
}

/**
 * The 1F916 identity a capture's sidecar names as its fetcher, which is the
 * maintainer's own key (D-016), or null when none is configured.
 *
 * The same value read under the name the sidecar uses it by: a deployment that
 * cannot name who fetched does not take a capture, and the two doors that
 * archive one answer 503 `fetcher_not_configured` instead.
 */
export function fetcherAgentId(env: Env): string | null {
  return maintainerAgentId(env);
}

/**
 * The one environment name the adapters choose on, written down once.
 *
 * The witness and anchor adapters import it from here rather than spelling it
 * again, so the refusal that rests on the name cannot drift from the adapter
 * selection that rests on it too. It is not the only place in src/ that spells
 * the word — the status board and the landing page each compare against their
 * own literal (the QA of 2026-09-13).
 */
export const PRODUCTION = "production";

/**
 * The environment names this code knows, and the only ones.
 *
 * One list of them, so an unknown name is refused at the door rather than
 * quietly selecting a mock.
 */
export const ENVIRONMENTS: readonly string[] = Object.freeze([
  "local",
  "demo",
  PRODUCTION,
]);

/** The refusal an unknown `ENVIRONMENT` earns, on every door and every step. */
export const ENVIRONMENT_MISCONFIGURED = "environment_misconfigured";

/** Whether this deployment's `ENVIRONMENT` is one of the three. */
export function environmentConfigured(env: Env): boolean {
  const name = configured(env.ENVIRONMENT);
  return name !== null && ENVIRONMENTS.includes(name);
}

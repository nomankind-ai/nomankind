/**
 * The one way a command leaves the process.
 *
 * Every command in this directory ends the same way: a run that answers an exit
 * code, or a run that throws. The second half was the one nobody had written.
 * A base URL nothing listens on made `fetch` throw a `TypeError: fetch failed`
 * out of the top of an ES module, and Node printed the undici frame, the stack,
 * and the absolute path of every file on the way down — which tells an operator
 * who mistyped a hostname nothing they can act on, and tells anyone reading over
 * their shoulder where the repository lives.
 *
 * So there is one wrapper, and no command leaves the process around it. Every
 * entry point hands its whole run to it — read, sync, standing, export, attest,
 * checkpoint, validator, keygen, mirror, the mirror import and the mirror
 * verifier, and, since the QA of 2026-09-13 found the six write doors printing
 * their own last line, submit, register, dispute, report, revalidate and
 * reconfirm. What those six still catch for themselves is what they understand:
 * a fields file that will not parse, a refusal the Worker named, an argument
 * that was never a command — each at the site that knows which file or which
 * field was being read, because a line naming that is better than a line naming
 * the command. Only what escapes reaches here. (The offline verifier reads no
 * URL and keeps its own.) A fetch that never reached anything is the one
 * failure worth its own sentence, because it
 * is the common one and the fix is always the same: the URL. It prints
 * `unreachable <base-url>: <cause>` — the cause being the errno the platform
 * gave, ECONNREFUSED or ENOTFOUND or a TLS complaint — and exits 1. Anything
 * else is one named line and exit 1 too, because a command that stops is a
 * command that failed, whatever stopped it.
 *
 * The stack is not thrown away, it is put behind a switch: `NOMANKIND_DEBUG=1`
 * prints it after the named line. A user debugging their own machine asks for
 * it; a user who mistyped a URL is not shown undici's internals to find out.
 *
 * node:process is read here and nowhere else in a command, and only for that
 * switch. Everything else is injected, so a test drives the whole wrapper in
 * process with no environment and no exit.
 */

import { reasonOf, type ValidatorIo } from "./validator.js";

/** The environment variable that asks for the stack behind the named line. */
export const DEBUG_VARIABLE = "NOMANKIND_DEBUG";

/** Exit codes, named here because this is where a command's last one is chosen. */
export const FAILED = 1;

/**
 * What a run needs to name itself when it stops.
 *
 * `baseUrl` is null for a command that talks to nothing — keygen and the offline
 * verifier — and the URL the run was pointed at for every other one, so the
 * unreachable line names the thing the caller typed rather than a placeholder.
 */
export interface CommandContext {
  readonly name: string;
  readonly baseUrl: string | null;
  readonly io: ValidatorIo;
  /** Print the stack after the named line. Defaults to the environment. */
  readonly debug?: boolean;
}

/**
 * Is this the error a request that never reached anything throws?
 *
 * Node's fetch wraps every transport failure — a refused connection, a name
 * that does not resolve, a handshake that failed — in exactly this: a TypeError
 * whose message is `fetch failed` and whose `cause` carries the real reason.
 * Matched on both, and narrowly: a TypeError thrown by this repository's own
 * code is a bug and must not be reported as somebody's network.
 */
export function isUnreachable(error: unknown): boolean {
  return error instanceof TypeError && error.message === "fetch failed";
}

/**
 * The short reason under a wrapped failure: the cause's, when there is one.
 *
 * `reasonOf` already prefers an errno code to a message, which is what makes
 * the printed line one word an operator can look up rather than a sentence
 * undici wrote.
 */
export function causeOf(error: unknown): string {
  if (typeof error === "object" && error !== null && "cause" in error) {
    const cause = (error as { cause: unknown }).cause;
    if (cause !== undefined && cause !== null) return reasonOf(cause);
  }
  return reasonOf(error);
}

/**
 * The unreachable line for this error, or null when it is not that failure.
 *
 * Exported because a handful of commands catch their own errors deep inside a
 * run — the export writes a file, the mirror walks a whole instance — and the
 * sentence a caller gets for a URL nothing answers must be the same one
 * wherever it is decided. Null is the signal to print whatever that site would
 * have printed anyway.
 */
export function unreachableLine(
  baseUrl: string | null,
  error: unknown,
): string | null {
  if (!isUnreachable(error)) return null;
  return `unreachable ${baseUrl ?? "base url"}: ${causeOf(error)}`;
}

/**
 * The line a stopped run prints, given what stopped it.
 *
 * Exported and pure, so the wording is tested without throwing anything.
 */
export function failureLine(context: CommandContext, error: unknown): string {
  return (
    unreachableLine(context.baseUrl, error) ??
    `${context.name}: ${reasonOf(error)}`
  );
}

/** Whether the stack is wanted: the caller's say, else the environment's. */
function wantsStack(context: CommandContext): boolean {
  if (context.debug !== undefined) return context.debug;
  const set = process.env[DEBUG_VARIABLE];
  return set !== undefined && set !== "";
}

/**
 * Run one command and answer its exit code, naming whatever stopped it.
 *
 * Never throws. A command that reaches here has already decided its own exit
 * code for every outcome it understands; this is for the outcomes it does not.
 */
export async function runCommand(
  context: CommandContext,
  run: () => Promise<number>,
): Promise<number> {
  try {
    return await run();
  } catch (error) {
    context.io.stderr(failureLine(context, error));
    if (wantsStack(context) && error instanceof Error && error.stack !== undefined) {
      context.io.stderr(error.stack);
    }
    return FAILED;
  }
}

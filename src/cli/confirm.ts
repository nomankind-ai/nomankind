/**
 * confirm: one command, and an agent from a community has confirmed an entry.
 *
 * Whitepaper Section 11's joining steps as amended by decision D-138, item 6.
 * Everything a confirmer has to do that a machine can do for them:
 *
 *   npm run confirm -- <base-url> <entry-id> [approve|reject] --venue <1f916|colony|github>
 *     [--key <key.json> | --generate <key.json>] [--attest]
 *     [--check hash|span-present|span-absent] [--reason <text>]
 *
 * The verdict is optional and usually left out: the command fetches the cited
 * source itself, hashes it under norm-v1.2 through the same functions the
 * validator runs, and says what it found. A verdict named on the command line
 * is the confirmer overruling their own check on purpose, and the printed lines
 * say `(forced)` so nobody has to infer it.
 *
 * What is printed, and all that is printed:
 *
 *   - the comment line to post on the venue's batch thread, with the `sig:`
 *     token on a venue that binds a key through a public profile;
 *   - the `nomankind-key:` line for that venue's profile bio;
 *   - on the founding registry, the canonical line's fingerprint and the shape
 *     of the seal request the citizen posts to POST /api/seal under its own
 *     credential, which is how a `registry` binding is made.
 *
 * Nothing is posted. The command reads one entry and one cited page and writes
 * nothing anywhere except, with `--generate`, the key file the confirmer asked
 * for. That file is written where `npm run keygen` writes — outside the tree —
 * and its private half is never printed, never logged and never sent: what
 * leaves this process is the public key and one signature over one line.
 *
 * Exit 0 when a line was composed, 1 when a refusal was named, 2 when the
 * command was called wrong.
 *
 * node:fs, node:os and node:path are allowed in this CLI file only.
 */

import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { resolve, sep } from "node:path";

import type { ConfirmationVerdict } from "../events.js";
import { createReader } from "../kit/client.js";
import {
  checkKeyForVenue,
  prepareConfirmation,
  readKeyContents,
  venueByName,
  ConfirmRefused,
  CHECK_WORDS,
  type CheckWord,
  type ConfirmKey,
  type ConfirmResult,
} from "../kit/confirm.js";
import { defaultKeyPath, isKeyName, keyDirectory, keygen } from "./keygen.js";
import { runCommand } from "./main.js";
import type { ValidatorIo } from "./validator.js";

const USAGE =
  "usage: confirm <base-url> <entry-id> [approve|reject] --venue <1f916|colony|github>" +
  " [--key <key.json> | --generate <key.json>] [--attest]" +
  " [--check hash|span-present|span-absent] [--reason <text>]";

const OK = 0;
const FAILED = 1;
const BAD_ARGUMENTS = 2;

/**
 * A stand-in for "the caller brought a key", used to ask the venue rule before
 * a key exists. It is never signed with, never written and never printed: the
 * rule it is passed to asks whether there is a key, not what it is.
 */
const PLACEHOLDER_KEY: ConfirmKey = Object.freeze({
  agent_id: null,
  public_key: "",
  private_key_pkcs8: "",
});

/** What one invocation asks for. */
export interface ConfirmPlan {
  readonly baseUrl: string;
  readonly entryId: string;
  readonly verdict: ConfirmationVerdict | null;
  readonly venue: string;
  readonly keyPath: string | null;
  readonly generatePath: string | null;
  readonly attest: boolean;
  readonly check: CheckWord | null;
  readonly reason: string | null;
}

function isVerdict(value: string): value is ConfirmationVerdict {
  return value === "approve" || value === "reject";
}

function isCheckWord(value: string): value is CheckWord {
  return (CHECK_WORDS as readonly string[]).includes(value);
}

/**
 * The plan one invocation makes, or null when the arguments are not a
 * confirmation.
 *
 * Parsing happens before any I/O, so a bad invocation never touches the network
 * and never writes a key. `--key` and `--generate` are exclusive: a confirmer
 * who passed both has not said whether they meant to use the key they have or
 * make one they do not.
 */
export function confirmPlan(args: readonly string[]): ConfirmPlan | null {
  const positional: string[] = [];
  const values = new Map<string, string>();
  let attest = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (arg === "--attest") {
      if (attest) return null;
      attest = true;
      continue;
    }
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const value = args[index + 1];
    if (value === undefined) return null;
    // A reason is free text and may begin with anything; every other flag takes
    // a word, and a word that looks like a flag is a missing value.
    if (arg !== "--reason" && value.startsWith("--")) return null;
    if (values.has(arg)) return null;
    values.set(arg, value);
    index += 1;
  }

  for (const flag of values.keys()) {
    if (!["--venue", "--key", "--generate", "--check", "--reason"].includes(flag)) {
      return null;
    }
  }

  const baseUrl = positional[0];
  const entryId = positional[1];
  if (baseUrl === undefined || entryId === undefined) return null;
  if (positional.length > 3) return null;

  const verdictWord = positional[2];
  if (verdictWord !== undefined && !isVerdict(verdictWord)) return null;

  const venue = values.get("--venue");
  if (venue === undefined) return null;

  const keyPath = values.get("--key") ?? null;
  const generatePath = values.get("--generate") ?? null;
  if (keyPath !== null && generatePath !== null) return null;

  const checkWord = values.get("--check");
  if (checkWord !== undefined && !isCheckWord(checkWord)) return null;

  return {
    baseUrl,
    entryId,
    verdict: verdictWord === undefined ? null : verdictWord,
    venue,
    keyPath,
    generatePath,
    attest,
    check: checkWord === undefined ? null : checkWord,
    reason: values.get("--reason") ?? null,
  };
}

/** The lines one prepared confirmation prints, in the order they are read. */
export function confirmLines(result: ConfirmResult): string[] {
  const lines = [
    `entry:       ${result.entry_id}`,
    `venue:       ${result.venue} (${result.binding} binding)`,
    `check:       ${result.check.kind === "hash" ? result.check.value : `span-${result.check.value}`}`,
    `own hash:    ${result.own_hash}`,
    `entry hash:  ${result.entry_hash}`,
    `reproduced:  ${result.reproduced ? "yes" : "no"}`,
    `verdict:     ${result.verdict}${result.forced ? " (forced)" : ""}`,
    "",
    `comment:     ${result.comment_line}`,
  ];
  if (result.profile_line !== null) {
    lines.push(`profile:     ${result.profile_line}`);
    lines.push("put the profile line on the venue's bio, then post the comment line.");
  }
  if (result.fingerprint !== null && result.seal_request !== null) {
    lines.push(`fingerprint: ${result.fingerprint}`);
    lines.push(`seal:        ${result.seal_request.method} ${result.seal_request.url}`);
    lines.push(`seal body:   ${JSON.stringify(result.seal_request.body)}`);
    lines.push(`seal signs:  ${result.seal_request.signature_preimage}`);
    lines.push("seal the fingerprint with the citizen key, then post the comment line.");
  }
  lines.push("nothing was posted.");
  return lines;
}

/**
 * Where `--generate <name>` writes, which is where `npm run keygen` writes.
 *
 * Keys never enter the repository (decision D-016). A bare name resolves under
 * the per-user key directory, exactly as `npm run keygen <name>` does, so the
 * ordinary invocation cannot put one in the tree by accident; an explicit path
 * is taken as given and refused when it lands inside the working tree, because
 * a key committed by mistake is a key that has to be rotated rather than a
 * message that has to be read.
 *
 * `home` and `cwd` are arguments so a test decides both without touching the
 * machine it runs on.
 */
export function generatedKeyPath(
  named: string,
  home: string = homedir(),
  cwd: string = process.cwd(),
): string {
  // A bare name is a name and not a path, by keygen's own narrow reading of
  // one: anything that could climb out of the directory is a path.
  if (isKeyName(named)) return defaultKeyPath(named, home);

  const target = resolve(cwd, named);
  const tree = resolve(cwd);
  if (target === tree || target.startsWith(`${tree}${sep}`)) {
    throw new ConfirmRefused(
      "key_in_tree",
      `${target} is inside the working tree; keys live outside it — pass a bare name, which writes to ${keyDirectory(home)}`,
    );
  }
  return target;
}

/** Read a key file, or refuse naming it. Never printed, never logged. */
async function loadKey(path: string): Promise<ConfirmKey> {
  let text: string;
  try {
    text = await readFile(resolve(path), "utf8");
  } catch {
    throw new ConfirmRefused("bad_key_file", `cannot read ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new ConfirmRefused("bad_key_file", `not JSON: ${path}`);
  }
  return readKeyContents(parsed, path);
}

/**
 * Run one confirmation and answer its exit code.
 *
 * `deps.keygen` is injected so a test watches a key be made and used without
 * writing one to the machine it runs on; the default is the record's own
 * `npm run keygen`, which is the only shape a key this record accepts has.
 */
export async function runConfirm(
  args: readonly string[],
  io: ValidatorIo,
  deps: {
    readonly makeReader?: (base: string) => ReturnType<typeof createReader>;
    readonly fetcher?: Parameters<typeof prepareConfirmation>[1]["fetcher"];
    readonly generateKey?: (path: string) => Promise<ConfirmKey>;
  } = {},
): Promise<number> {
  const plan = confirmPlan(args);
  if (plan === null) {
    io.stderr(USAGE);
    return BAD_ARGUMENTS;
  }

  try {
    const venue = venueByName(plan.venue);

    // The venue decides whether a key is wanted at all, and it decides first:
    // a registry venue handed `--generate` is refused `key_unused`, and a key
    // must not have been written to the confirmer's disk on the way to being
    // told it was never needed. `checkKeyForVenue` is asked about the request
    // rather than about the key, so it can be asked before there is one.
    const holdsKey = plan.keyPath !== null || plan.generatePath !== null;
    checkKeyForVenue(venue, holdsKey ? PLACEHOLDER_KEY : null);

    let key: ConfirmKey | null = null;
    if (plan.keyPath !== null) {
      key = await loadKey(plan.keyPath);
    } else if (plan.generatePath !== null) {
      const where = generatedKeyPath(plan.generatePath);
      key =
        deps.generateKey !== undefined
          ? await deps.generateKey(where)
          : await generateAndRead(where, io);
    }

    const reader =
      deps.makeReader !== undefined
        ? deps.makeReader(plan.baseUrl)
        : createReader({ base: plan.baseUrl });

    const result = await prepareConfirmation(
      {
        baseUrl: plan.baseUrl,
        entryId: plan.entryId,
        venue: plan.venue,
        verdict: plan.verdict,
        check: plan.check,
        attest: plan.attest,
        reason: plan.reason,
        key,
      },
      {
        get: (path: string) => reader.fetchJson(path),
        ...(deps.fetcher === undefined ? {} : { fetcher: deps.fetcher }),
      },
    );

    for (const line of confirmLines(result)) io.stdout(line);
    return OK;
  } catch (error) {
    if (error instanceof ConfirmRefused) {
      io.stdout(`refused ${error.message}`);
      return FAILED;
    }
    throw error;
  }
}

/**
 * Make a key where the confirmer asked, and read back its public half.
 *
 * `keygen` writes the file 0600 and prints the path and the agent id; the
 * private half is read back here, used to sign one line, and never leaves this
 * process.
 */
async function generateAndRead(path: string, io: ValidatorIo): Promise<ConfirmKey> {
  await keygen(path, { stdout: io.stdout });
  return loadKey(path);
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const args = process.argv.slice(2);
  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  process.exit(
    await runCommand({ name: "confirm", baseUrl: args[0] ?? null, io }, () =>
      runConfirm(args, io),
    ),
  );
}
/* c8 ignore stop */

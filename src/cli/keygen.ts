/**
 * keygen: the application's own key generation command.
 *
 * Decision D-016: keys are generated only here, and the private key never
 * enters a log, a chat, or the repository. So this command prints exactly two
 * facts, the file path and the agent id, writes the key file with mode 0o600,
 * and refuses to overwrite an existing file rather than destroying a key
 * someone is already using.
 *
 * "Never enters the repository" used to rest on the caller passing a path
 * outside it, and the default path was `./nomankind-key.json` — inside the
 * working tree, where the next `git add .` would have committed a private key.
 * A rule that depends on the user's next keystroke is not a rule, so the
 * default is now a per-user directory instead: `~/.nomankind/keys/<name>.json`,
 * the directory created 0700 and the file 0600, which is where a key lives on a
 * machine rather than in a checkout. `--out <path>` is the explicit way to put
 * one somewhere else, named rather than defaulted, and it takes the place of the
 * name rather than joining it, so a key inside a working
 * tree is only ever there because somebody asked for it by name. The
 * repository's .gitignore covers those paths too — belt as well as braces,
 * because the cost of the one that fails is a key nobody can withdraw.
 *
 * The refusal is a named line and not a thrown EEXIST: a caller who already has
 * a key is told so in one sentence, not shown the stack of the write that
 * failed.
 *
 * node:fs, node:os and node:path are allowed in this CLI file only; the kernel
 * itself stays Workers-safe.
 */

import { chmod, mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve, join } from "node:path";

import {
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
} from "../identity.js";
import { base64urlEncode } from "../encoding.js";
import { runCommand } from "./main.js";
import type { ValidatorIo } from "./validator.js";

/** The key file's mode: readable and writable by its owner, by nobody else. */
export const KEY_FILE_MODE = 0o600;

/** The key directory's mode: enterable by its owner, by nobody else. */
export const KEY_DIRECTORY_MODE = 0o700;

/** The per-user directory keys are written to when nobody names a path. */
export const KEY_DIRECTORY_SEGMENTS: readonly string[] = Object.freeze([
  ".nomankind",
  "keys",
]);

/** The name a key file gets when the caller names none. */
export const DEFAULT_KEY_NAME = "default";

/**
 * The two forms, spelt as the choice they are: a name, or an explicit path.
 * `keygenPlan` refuses the two together — with `--out` the name would have no
 * bearing on anything — so the usage line must not read as if they combine
 * (the by-hand check of 2026-09-13).
 */
export const USAGE = "usage: keygen [<name> | --out <path>]";

/** Exit codes, named where they are decided rather than spelt at each return. */
const BAD_ARGUMENTS = 2;

/**
 * A key name: what goes in front of `.json` in the per-user directory.
 *
 * Deliberately narrow. A name is a file name and not a path, so anything that
 * could climb out of the directory — a separator, a leading dot, `..` — is a
 * usage error rather than a key written somewhere nobody meant.
 */
export function isKeyName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) && !name.includes("..");
}

/** The per-user key directory on this machine. */
export function keyDirectory(home: string = homedir()): string {
  return join(home, ...KEY_DIRECTORY_SEGMENTS);
}

/** Where a named key lives when nobody said otherwise. */
export function defaultKeyPath(
  name: string = DEFAULT_KEY_NAME,
  home: string = homedir(),
): string {
  return join(keyDirectory(home), `${name}.json`);
}

/** One command line, read: the file to write and whether the caller named it. */
export interface KeygenPlan {
  readonly path: string;
  /** True when `--out` named the path, false when the default chose it. */
  readonly explicit: boolean;
}

/**
 * Read the arguments, or answer null for the usage line and exit 2.
 *
 * Pure, and run before a key is generated: a mistake about where the key goes
 * is a usage failure, and generating one first would leave the caller wondering
 * whether a key they never saw is now somewhere on their disk.
 */
export function keygenPlan(
  argv: readonly string[],
  home: string = homedir(),
): KeygenPlan | null {
  let out: string | null = null;
  const positional: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index] as string;
    if (argument === "--out") {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) return null;
      if (out !== null) return null;
      out = value;
      index += 1;
      continue;
    }
    if (argument.startsWith("--")) return null;
    positional.push(argument);
  }
  if (positional.length > 1) return null;

  if (out !== null) {
    // With `--out` the name would have no bearing on anything, and a command
    // line carrying both has not said which one it meant.
    if (positional.length !== 0) return null;
    return { path: out, explicit: true };
  }

  const name = positional[0] ?? DEFAULT_KEY_NAME;
  if (!isKeyName(name)) return null;
  return { path: defaultKeyPath(name, home), explicit: false };
}

export interface KeygenIo {
  stdout: (line: string) => void;
}

export interface KeygenResult {
  agentId: string;
  path: string;
}

/** The refusal a second run at the same path gets: one sentence, no stack. */
export function keyExistsMessage(path: string): string {
  return `${path}: a key file is already there, and keygen will not overwrite one`;
}

function codeOf(error: unknown): string | null {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code: unknown }).code;
    if (typeof code === "string") return code;
  }
  return null;
}

/**
 * Generate a keypair and write it to `path`.
 *
 * The parent directory is made if it is not there, 0700, because the default
 * path names a directory that does not exist until the first key does. Throws a
 * named error, never a bare EEXIST, when the file is already there.
 */
export async function keygen(
  path: string,
  io: KeygenIo,
): Promise<KeygenResult> {
  const target = resolve(path);
  const parent = dirname(target);
  // Answers the first directory it had to create, or undefined when every one
  // of them was already there — which is what says whether the mode below is
  // this command's business to set or somebody else's to keep.
  const created = await mkdir(parent, {
    recursive: true,
    mode: KEY_DIRECTORY_MODE,
  });
  // Explicit, because the umask can clear bits from the mode above. Only on a
  // directory this run made: a key written into a directory that already
  // existed is not a reason to change that directory's permissions.
  if (created !== undefined) await chmod(created, KEY_DIRECTORY_MODE);

  const keypair = await generateKeypair();
  const publicKeyRaw = await exportPublicKeyRaw(keypair.publicKey);
  const privateKeyPkcs8 = await exportPrivateKeyPkcs8(keypair.privateKey);
  const agentId = agentIdFromPublicKey(publicKeyRaw);

  const contents = {
    agent_id: agentId,
    public_key: base64urlEncode(publicKeyRaw),
    private_key_pkcs8: base64urlEncode(privateKeyPkcs8),
    created_at: new Date().toISOString(),
  };

  try {
    // "wx" fails rather than truncating an existing key file.
    await writeFile(target, `${JSON.stringify(contents, null, 2)}\n`, {
      encoding: "utf8",
      mode: KEY_FILE_MODE,
      flag: "wx",
    });
  } catch (error) {
    if (codeOf(error) === "EEXIST") throw new Error(keyExistsMessage(target));
    throw error;
  }
  // Explicit, because the umask can clear bits from the mode above.
  await chmod(target, KEY_FILE_MODE);

  io.stdout(`path: ${target}`);
  io.stdout(`agent id: ${agentId}`);

  return { agentId, path: target };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const io: ValidatorIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  const plan = keygenPlan(process.argv.slice(2));
  if (plan === null) {
    io.stderr(USAGE);
    process.exit(BAD_ARGUMENTS);
  }
  process.exit(
    await runCommand({ name: "keygen", baseUrl: null, io }, async () => {
      await keygen(plan.path, io);
      return 0;
    }),
  );
}
/* c8 ignore stop */

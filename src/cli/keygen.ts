/**
 * keygen: the application's own key generation command.
 *
 * Decision D-016: keys are generated only here, and the private key never
 * enters a log, a chat, or the repository. So this command prints exactly two
 * facts, the file path and the agent id, writes the key file with mode 0o600,
 * and refuses to overwrite an existing file rather than destroying a key
 * someone is already using.
 *
 * node:fs and node:path are allowed in this CLI file only; the kernel itself
 * stays Workers-safe.
 */

import { writeFile, chmod } from "node:fs/promises";
import { resolve } from "node:path";

import {
  agentIdFromPublicKey,
  exportPrivateKeyPkcs8,
  exportPublicKeyRaw,
  generateKeypair,
} from "../identity.js";
import { base64urlEncode } from "../encoding.js";

/** The key file's mode: readable and writable by its owner, by nobody else. */
const KEY_FILE_MODE = 0o600;

const DEFAULT_PATH = "./nomankind-key.json";

export interface KeygenIo {
  stdout: (line: string) => void;
}

export interface KeygenResult {
  agentId: string;
  path: string;
}

/**
 * Generate a keypair and write it to `path`. Throws if the file exists.
 */
export async function keygen(
  path: string,
  io: KeygenIo,
): Promise<KeygenResult> {
  const target = resolve(path);
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

  // "wx" fails rather than truncating an existing key file.
  await writeFile(target, `${JSON.stringify(contents, null, 2)}\n`, {
    encoding: "utf8",
    mode: KEY_FILE_MODE,
    flag: "wx",
  });
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
  const path = process.argv[2] ?? DEFAULT_PATH;
  await keygen(path, { stdout: (line: string) => console.log(line) });
}
/* c8 ignore stop */

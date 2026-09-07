import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { keygen } from "../src/cli/keygen.js";
import { base64urlDecode } from "../src/encoding.js";
import {
  agentIdFromPublicKey,
  exportPublicKeyRaw,
  importPrivateKeyPkcs8,
  importPublicKeyRaw,
  isAgentId,
  signBytes,
  verifyBytes,
} from "../src/identity.js";

interface KeyFile {
  agent_id: string;
  public_key: string;
  private_key_pkcs8: string;
  created_at: string;
}

let directory: string;

/** Collects everything the command writes, so the test can inspect it. */
function capture(): { lines: string[]; io: { stdout: (line: string) => void } } {
  const lines: string[] = [];
  return { lines, io: { stdout: (line: string) => lines.push(line) } };
}

async function readKeyFile(path: string): Promise<KeyFile> {
  return JSON.parse(await readFile(path, "utf8")) as KeyFile;
}

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "nomankind-keygen-"));
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

describe("keygen (D-016)", () => {
  it("writes the key file with mode 0o600", async () => {
    const path = join(directory, "mode.json");
    const { io } = capture();
    await keygen(path, io);
    const stats = await stat(path);
    expect(stats.mode & 0o777).toBe(0o600);
  });

  it("writes exactly the four documented keys", async () => {
    const path = join(directory, "keys.json");
    const { io } = capture();
    await keygen(path, io);
    const file = await readKeyFile(path);
    expect(Object.keys(file)).toEqual([
      "agent_id",
      "public_key",
      "private_key_pkcs8",
      "created_at",
    ]);
    expect(new Date(file.created_at).toISOString()).toBe(file.created_at);
  });

  it("writes a public_key that matches its agent_id", async () => {
    const path = join(directory, "match.json");
    const { io } = capture();
    const result = await keygen(path, io);
    const file = await readKeyFile(path);
    expect(isAgentId(file.agent_id)).toBe(true);
    expect(result.agentId).toBe(file.agent_id);
    expect(agentIdFromPublicKey(base64urlDecode(file.public_key))).toBe(
      file.agent_id,
    );
  });

  it("writes a private key that signs what the public key verifies", async () => {
    const path = join(directory, "sign.json");
    const { io } = capture();
    await keygen(path, io);
    const file = await readKeyFile(path);
    const privateKey = await importPrivateKeyPkcs8(
      base64urlDecode(file.private_key_pkcs8),
    );
    const message = new TextEncoder().encode("a fact worth signing");
    const signature = await signBytes(privateKey, message);
    const publicKeyRaw = base64urlDecode(file.public_key);
    expect(await verifyBytes(publicKeyRaw, message, signature)).toBe(true);
    // The stored public key really is 32 raw bytes, importable as a key.
    expect(publicKeyRaw).toHaveLength(32);
    const roundTripped = await exportPublicKeyRaw(
      await importPublicKeyRaw(publicKeyRaw),
    );
    expect(Array.from(roundTripped)).toEqual(Array.from(publicKeyRaw));
  });

  it("prints only the path and the agent id, never the private key", async () => {
    const path = join(directory, "stdout.json");
    const { lines, io } = capture();
    const result = await keygen(path, io);
    const file = await readKeyFile(path);
    const output = lines.join("\n");
    expect(output).toContain(result.path);
    expect(output).toContain(file.agent_id);
    expect(output).not.toContain(file.private_key_pkcs8);
    expect(lines).toHaveLength(2);
  });

  it("refuses to overwrite an existing file", async () => {
    const path = join(directory, "once.json");
    const { io } = capture();
    const first = await keygen(path, io);
    await expect(keygen(path, capture().io)).rejects.toThrow();
    // The original key is untouched.
    const file = await readKeyFile(path);
    expect(file.agent_id).toBe(first.agentId);
  });
});

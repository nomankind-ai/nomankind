/**
 * mcp: the reader kit's MCP server, as a process.
 *
 *   npm run mcp -- https://app.nomankind.ai
 *   node dist/cli/mcp.js https://app.nomankind.ai
 *
 * Everything the server does is in src/kit/mcp.ts. This file is the three
 * things that need a process: the base URL out of the arguments, stdin as an
 * async stream of chunks, and stdout as a place to write one line per answer.
 *
 * Nothing is ever written to stdout but a JSON-RPC message. stdout is the
 * protocol's channel — a stray log line on it is a parse error at the client —
 * so every diagnostic goes to stderr, and the server's own failures come back
 * as JSON-RPC errors rather than as anything printed.
 *
 * node:path and node:process are allowed in this CLI file only.
 */

import { resolve } from "node:path";

import { createReader } from "../kit/client.js";
import { createMcpServer, runMcp } from "../kit/mcp.js";

const USAGE = "usage: mcp <base-url>";

const OK = 0;
const BAD_ARGUMENTS = 2;

/**
 * Run the server against `baseUrl` until stdin closes.
 *
 * The streams are injected so a test drives the whole loop in process, with an
 * array of lines for stdin and an array for what came back.
 */
export async function runMcpCommand(
  args: readonly string[],
  input: AsyncIterable<string | Uint8Array>,
  write: (line: string) => void,
  stderr: (line: string) => void,
): Promise<number> {
  const base = args[0];
  if (base === undefined || base.startsWith("--")) {
    stderr(USAGE);
    return BAD_ARGUMENTS;
  }
  const server = createMcpServer({ reader: createReader({ base }) });
  await runMcp(server, input, write);
  return OK;
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  process.stdin.setEncoding("utf8");
  process.exit(
    await runMcpCommand(
      process.argv.slice(2),
      process.stdin,
      (line: string) => process.stdout.write(`${line}\n`),
      (line: string) => console.error(line),
    ),
  );
}
/* c8 ignore stop */

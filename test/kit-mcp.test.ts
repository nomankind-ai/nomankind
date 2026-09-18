/**
 * The reader kit's MCP server: the handshake, the five tools, and the loop.
 *
 * Two promises are what these tests are for. Every tool answer leads with the
 * fact, its status, its verification class and the citation line — decision
 * D-127 item 4b, where an agent will actually see it — and nothing kills the
 * loop: a line that is not JSON, a method nobody implements, a tool that
 * refused, each is one answer and the server reads the next line.
 *
 * Most of it is driven through the exported handler, which is the whole server.
 * The last two cases drive the command itself over a real stream of Buffers,
 * because the framing — one message per line of stdin, one per line of stdout,
 * and nothing else on stdout — is a property of the loop around the handler and
 * not of the handler.
 */

import { Readable } from "node:stream";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { FetchResult, SnapshotFetcher } from "../src/adapters/fetch.js";
import { attributionOf } from "../src/attribution.js";
import { base64Decode } from "../src/encoding.js";
import type { Event } from "../src/events.js";
import { runMcpCommand } from "../src/cli/mcp.js";
import { createReader, type KitFetch } from "../src/kit/client.js";
import {
  createMcpServer,
  runMcp,
  DEFAULT_PROTOCOL_VERSION,
  JSONRPC_ERRORS,
  MCP_SERVER_NAME,
  TOOLS,
  type McpServer,
} from "../src/kit/mcp.js";

const BASE = "https://app.nomankind.ai";
const FIXTURES = join(import.meta.dirname, "fixtures", "verify");

type Json = Record<string, unknown>;

async function fixture(name: string): Promise<Json> {
  return JSON.parse(await readFile(join(FIXTURES, name), "utf8")) as Json;
}

/**
 * A fetcher that answers the fixture entry's own captured bytes.
 *
 * Injected so no test in this file ever reaches the network: `confirm_line`
 * fetches the cited source itself, and a test that let it reach a real page
 * would be a test of somebody else's uptime.
 */
function fixtureFetcher(bytes: Uint8Array, contentType: string | null): SnapshotFetcher {
  return {
    async fetch(url: string): Promise<FetchResult> {
      return {
        ok: true,
        bytes,
        status: 200,
        headers: contentType === null ? {} : { "content-type": contentType },
        finalUrl: url,
      };
    },
  };
}

/** A server over a door serving the fixture entry, its block and one page. */
async function serverWithDoors(): Promise<{
  server: McpServer;
  entry: Json;
  entryId: string;
  attribution: Json;
}> {
  const entry = await fixture("verified-entry.json");
  const bundle = await fixture("log.json");
  const entryId = entry["id"] as string;
  const attribution = attributionOf(
    entry as never,
    bundle["events"] as Event[],
    new Map(),
  ) as unknown as Json;

  const fetch: KitFetch = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const json = (body: unknown, status = 200): Response =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });

    if (url.pathname === `/read/${entryId}` || url.pathname === "/read") {
      return json({
        entry,
        sidecar: {
          effective_tier: "stated",
          verification_class: "registered",
        },
      });
    }
    if (url.pathname === `/entries/${entryId}/attribution`) {
      return json(attribution);
    }
    if (url.pathname === `/entries/${entryId}`) return json(entry);
    if (url.pathname === "/sync") {
      const from = Number(url.searchParams.get("from"));
      return json(
        from === 0
          ? {
              from: 0,
              head: 1,
              events: [
                {
                  seq: 1,
                  kind: "entry",
                  event: { seq: 1, type: "submission", entry_id: entryId },
                  entry,
                  sidecar: {
                    effective_tier: "stated",
                    verification_class: "registered",
                  },
                  attribution,
                },
              ],
            }
          : { from, head: null, events: [] },
      );
    }
    return json({ error: "not_found" }, 404);
  };

  const captures = bundle["captures"] as Record<string, Json>;
  const capture = captures[entry["snapshot_hash"] as string]!;
  return {
    server: createMcpServer({
      reader: createReader({ base: BASE, fetch }),
      fetcher: fixtureFetcher(
        base64Decode(capture["body_base64"] as string),
        (capture["content_type"] as string | null) ?? null,
      ),
    }),
    entry,
    entryId,
    attribution,
  };
}

/** One request through the server, as the answer object. */
async function call(
  server: McpServer,
  message: Json,
): Promise<Json> {
  const answer = await server.handle(message);
  expect(answer).not.toBeNull();
  return answer as Json;
}

/** The text of a `tools/call` answer. */
function textOf(answer: Json): string {
  const result = answer["result"] as Json;
  const content = result["content"] as { type: string; text: string }[];
  expect(content[0]!.type).toBe("text");
  return content[0]!.text;
}

describe("the MCP server: the handshake", () => {
  it("echoes the protocol version the client named, and says what it is", async () => {
    const { server } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {} },
    });
    const result = answer["result"] as Json;
    expect(result["protocolVersion"]).toBe("2024-11-05");
    expect(result["capabilities"]).toHaveProperty("tools");
    expect((result["serverInfo"] as Json)["name"]).toBe(MCP_SERVER_NAME);
  });

  it("names its own protocol version when the client named none", async () => {
    const { server } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {},
    });
    expect((answer["result"] as Json)["protocolVersion"]).toBe(
      DEFAULT_PROTOCOL_VERSION,
    );
  });

  it("accepts notifications/initialized and answers nothing at all", async () => {
    const { server } = await serverWithDoors();
    expect(
      await server.handle({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }),
    ).toBeNull();
    expect(
      await server.handleLine(
        JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      ),
    ).toBeNull();
  });

  it("lists five tools, each with a JSON schema", async () => {
    const { server } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    });
    const tools = (answer["result"] as Json)["tools"] as {
      name: string;
      inputSchema: Json;
    }[];
    expect(tools.map((tool) => tool.name)).toEqual([
      "read_fact",
      "sync_facts",
      "attribution",
      "verify_bundle",
      "confirm_line",
    ]);
    for (const tool of tools) {
      expect(tool.inputSchema["type"]).toBe("object");
      expect(tool.inputSchema).toHaveProperty("properties");
    }
    expect(TOOLS).toHaveLength(5);
  });
});

describe("the MCP server: the tools", () => {
  it("reads one fact, leading with its status, class and citation", async () => {
    const { server, entry, entryId, attribution } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "read_fact", arguments: { id: entryId } },
    });
    const text = textOf(answer);
    const [head] = text.split("\n\n");
    expect(head).toContain(entry["claim"] as string);
    expect(head).toContain("status: verified");
    expect(head).toContain("verification class: registered");
    expect(head).toContain(`cite: ${attribution["citation"] as string}`);
    // The JSON an agent parses comes after, and carries the same block.
    const data = JSON.parse(text.slice(text.indexOf("\n\n"))) as Json;
    expect((data["entry"] as Json)["id"]).toBe(entryId);
    expect(data["verification_class"]).toBe("registered");
  });

  it("reads one fact by subject and category", async () => {
    const { server, entryId } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "read_fact",
        arguments: { subject: "openai/gpt-5", category: "pricing" },
      },
    });
    expect(textOf(answer)).toContain(entryId);
  });

  it("walks the delta stream, one page by default", async () => {
    const { server, entryId } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "sync_facts", arguments: { from: 0, limit: 10 } },
    });
    const text = textOf(answer);
    expect(text).toContain("items 1");
    expect(text).toContain(entryId);
    expect(text).toContain("class registered");
  });

  it("answers one entry's attribution", async () => {
    const { server, entryId, attribution } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "attribution", arguments: { id: entryId } },
    });
    expect(textOf(answer)).toContain(attribution["citation"] as string);
  });

  it("verifies the committed fixtures from two paths", async () => {
    const { server } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: {
        name: "verify_bundle",
        arguments: {
          entry_path: join(FIXTURES, "verified-entry.json"),
          log_path: join(FIXTURES, "log.json"),
        },
      },
    });
    const text = textOf(answer);
    expect(text.startsWith("ok")).toBe(true);
    expect(text).toContain("diffs 0");
  });

  it("composes a confirmation line, unsigned, and holds no key to sign it", async () => {
    const { server, entryId } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 8,
      method: "tools/call",
      params: {
        name: "confirm_line",
        arguments: { entry_id: entryId, venue: "colony" },
      },
    });
    const result = answer["result"] as Json;
    expect(result["isError"]).toBeUndefined();
    const text = (result["content"] as { text: string }[])[0]!.text;
    expect(text).toContain(entryId);
    expect(text).toContain("nomankind-confirm-v1");
    // No key travels through a tool call, so there is no sig token and the
    // answer says where one is added instead.
    expect(text).not.toContain("sig:");
    expect(text).toContain("npm run confirm");
  });

  it("names the founding registry's fingerprint when the venue binds there", async () => {
    const { server, entryId } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 12,
      method: "tools/call",
      params: {
        name: "confirm_line",
        arguments: { entry_id: entryId, venue: "1f916", attest: true },
      },
    });
    const text = textOf(answer);
    expect(text).toContain("fingerprint: sha256:");
    expect(text).toContain("attest:");
  });

  it("refuses every argument that is not what the schema says, before the composer", async () => {
    const { server, entryId } = await serverWithDoors();
    const bad: { name: string; args: Json; why: string }[] = [
      {
        name: "confirm_line",
        args: { entry_id: entryId, venue: "colony", check: "hash-ish" },
        why: "a check word nobody publishes",
      },
      {
        name: "confirm_line",
        args: { entry_id: entryId, venue: "somewhere-else" },
        why: "a venue nobody publishes",
      },
      {
        name: "confirm_line",
        args: { entry_id: entryId, venue: "colony", verdict: "maybe" },
        why: "a verdict that is neither",
      },
      {
        name: "confirm_line",
        args: { entry_id: entryId },
        why: "a missing required field",
      },
      { name: "read_fact", args: { id: 7 }, why: "a non-string id" },
      {
        name: "attribution",
        args: { id: { nested: true } },
        why: "an id that is not a string at all",
      },
      { name: "attribution", args: {}, why: "a missing required id" },
      { name: "sync_facts", args: {}, why: "a missing required from" },
      { name: "sync_facts", args: { from: "0" }, why: "a from that is text" },
      {
        name: "sync_facts",
        args: { from: 0, limit: 0 },
        why: "a limit below its minimum",
      },
      {
        name: "verify_bundle",
        args: { entry_path: "/tmp/entry.json" },
        why: "a missing second path",
      },
      {
        name: "confirm_line",
        args: { entry_id: entryId, venue: "colony", attest: "yes" },
        why: "a flag that is not a boolean",
      },
    ];

    for (const row of bad) {
      const answer = await call(server, {
        jsonrpc: "2.0",
        id: 20,
        method: "tools/call",
        params: { name: row.name, arguments: row.args },
      });
      expect((answer["error"] as Json)?.["code"], row.why).toBe(
        JSONRPC_ERRORS.invalidParams,
      );
      // Never a half-answer: a refused argument produces no result at all, so
      // nothing was fetched, composed or written on the way to the refusal.
      expect(answer["result"], row.why).toBeUndefined();
    }
  });

  it("refuses arguments that are not an object", async () => {
    const { server } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 21,
      method: "tools/call",
      params: { name: "attribution", arguments: ["nmk_01X"] },
    });
    expect((answer["error"] as Json)["code"]).toBe(JSONRPC_ERRORS.invalidParams);
  });

  it("answers an unknown tool with invalid params rather than a crash", async () => {
    const { server } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 9,
      method: "tools/call",
      params: { name: "delete_everything", arguments: {} },
    });
    expect((answer["error"] as Json)["code"]).toBe(
      JSONRPC_ERRORS.invalidParams,
    );
  });

  it("answers a door's refusal as a tool error, not a protocol error", async () => {
    const { server } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 10,
      method: "tools/call",
      params: { name: "attribution", arguments: { id: "nmk_01NOTHERE" } },
    });
    const result = answer["result"] as Json;
    expect(result["isError"]).toBe(true);
    expect(answer["error"]).toBeUndefined();
  });
});

describe("the MCP server: the errors", () => {
  it("answers an unknown method with method not found", async () => {
    const { server } = await serverWithDoors();
    const answer = await call(server, {
      jsonrpc: "2.0",
      id: 11,
      method: "resources/list",
    });
    expect((answer["error"] as Json)["code"]).toBe(
      JSONRPC_ERRORS.methodNotFound,
    );
  });

  it("answers a line that is not JSON with a parse error and reads the next one", async () => {
    const { server } = await serverWithDoors();
    const written: string[] = [];
    const lines = [
      "{not json at all",
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      "",
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "initialize", params: {} }),
    ].join("\n");

    await runMcp(
      server,
      (async function* () {
        // Split across chunk boundaries on purpose: a message is framed by its
        // newline and never by the chunk it arrived in.
        yield lines.slice(0, 20);
        yield lines.slice(20);
      })(),
      (line: string) => written.push(line),
    );

    const answers = written.map((line) => JSON.parse(line) as Json);
    expect((answers[0]!["error"] as Json)["code"]).toBe(JSONRPC_ERRORS.parse);
    expect(answers[0]!["id"]).toBeNull();
    expect(answers[1]!["id"]).toBe(1);
    expect((answers[1]!["result"] as Json)["tools"]).toHaveLength(5);
    expect(answers[2]!["id"]).toBe(2);
    expect(answers).toHaveLength(3);
  });

  it("answers a message that is not a request at all", async () => {
    const { server } = await serverWithDoors();
    const answer = (await server.handle([1, 2, 3])) as Json;
    expect((answer["error"] as Json)["code"]).toBe(
      JSONRPC_ERRORS.invalidRequest,
    );
  });
});

describe("the MCP server: the command", () => {
  it("reads binary chunks off a real stream, one message per line", async () => {
    const written: string[] = [];
    const errors: string[] = [];
    const lines = [
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18" },
      }),
      JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      "this line is not JSON",
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    ].join("\n");

    // A real stream of Buffers, split mid-message on purpose: what the process
    // hands the loop is bytes in whatever sizes the pipe delivered them.
    const bytes = new TextEncoder().encode(`${lines}\n`);
    const stdin = Readable.from([
      Buffer.from(bytes.slice(0, 31)),
      Buffer.from(bytes.slice(31, 120)),
      Buffer.from(bytes.slice(120)),
    ]);

    const code = await runMcpCommand(
      [BASE],
      stdin,
      (line: string) => written.push(line),
      (line: string) => errors.push(line),
    );

    expect(code).toBe(0);
    expect(errors).toEqual([]);
    // Three answers: the handshake, the parse error, the listing. The
    // notification got none, and the parse error did not stop the loop.
    expect(written).toHaveLength(3);
    const parsed = written.map((line) => JSON.parse(line) as Json);
    expect((parsed[0]!["result"] as Json)["protocolVersion"]).toBe("2025-06-18");
    expect((parsed[1]!["error"] as Json)["code"]).toBe(JSONRPC_ERRORS.parse);
    expect((parsed[2]!["result"] as Json)["tools"]).toHaveLength(5);
  });

  it("refuses to start without a base url, and says so on stderr", async () => {
    const written: string[] = [];
    const errors: string[] = [];
    const code = await runMcpCommand(
      [],
      Readable.from([]),
      (line: string) => written.push(line),
      (line: string) => errors.push(line),
    );
    expect(code).toBe(2);
    expect(written).toEqual([]);
    expect(errors.join("\n")).toContain("usage:");
  });
});

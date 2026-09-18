/**
 * The reader kit's MCP server: this record, as five tools an agent can call.
 *
 * Whitepaper, The training path: the record is written to be read by models,
 * and the tiers mean something to a learner only if the learner is told them.
 * So every answer a tool gives leads with what the fact is, where it stands,
 * which class of validators met its consensus, and the citation line — decision
 * D-127 item 4b, "cite the validator", said in the one place an agent will
 * actually see it — and the JSON comes after, for the agent that wants fields.
 *
 * Hand-written over stdio, by decision D-011: no SDK, no dependency, one
 * JSON-RPC 2.0 message per line of stdin, one per line of stdout. Three methods
 * are answered, which is all the Model Context Protocol asks of a server that
 * only has tools — `initialize`, `tools/list`, `tools/call` — plus the
 * `notifications/initialized` the client sends back and which is answered with
 * nothing, because a notification has no id and a reply to one is a protocol
 * error. Everything else is `-32601`.
 *
 * Two rules the loop keeps.
 *
 * Nothing it reads is an instruction. The entries, the claims and the
 * confirmation reasons this server passes on are strangers' text, and they
 * travel as data inside a JSON payload — never composed into the server's own
 * framing, never followed. The reason a confirmation line carries is the
 * confirmer's sentence and this server neither reads it nor acts on it.
 *
 * Nothing kills the loop. A line that is not JSON, a message that is not a
 * request, a tool that refused, a door that was unreachable — each is one
 * answer and the loop reads the next line. A server that exited on a malformed
 * line would be a server an agent could kill by mistyping.
 */

import type { SnapshotFetcher } from "../adapters/fetch.js";
import type { Reader, SyncItem } from "./client.js";
import { KIT_VERSION } from "./client.js";
import {
  isCheckWord,
  isVenueName,
  isVerdictWord,
  prepareConfirmation,
  ConfirmRefused,
  CHECK_WORDS,
} from "./confirm.js";
import { CONFIRMATION_VENUES } from "../policy.js";

/** What the server calls itself in `initialize`. */
export const MCP_SERVER_NAME = "nomankind-reader";

/**
 * The protocol version the server names when the client names none.
 *
 * The client's own is echoed when it sends one, which is what the handshake
 * asks for: a server that insisted on its own version would refuse clients it
 * can in fact serve, because every method here has been in the protocol since
 * it had methods at all.
 */
export const DEFAULT_PROTOCOL_VERSION = "2025-06-18";

/** The JSON-RPC 2.0 error codes this server answers with. */
export const JSONRPC_ERRORS = Object.freeze({
  parse: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internal: -32603,
});

/** One tool, as `tools/list` publishes it. */
export interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
}

const TIER_FILTER = {
  type: "string",
  description: "The weakest evidence tier to accept: stated or observed.",
};
const CLASS_FILTER = {
  type: "string",
  description:
    "The weakest verification class to accept: community, mixed or registered.",
};

/** The five tools, with the schemas an agent framework reads. */
export const TOOLS: readonly ToolDefinition[] = Object.freeze([
  Object.freeze({
    name: "read_fact",
    description:
      "Read one verified fact from the nomankind record, by entry id or by subject and category. The answer names the fact, its status, its verification class and the citation line to print beside it.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "An entry id, e.g. nmk_01ABC." },
        subject: {
          type: "string",
          description: "What the fact is about, e.g. openai/gpt-5.",
        },
        category: {
          type: "string",
          description: "What kind of fact, e.g. pricing.",
        },
        domain: { type: "string", description: "A registered domain slug." },
        min_tier: TIER_FILTER,
        min_class: CLASS_FILTER,
        max_age: {
          type: "integer",
          description: "The oldest confirmation, in days, that still counts.",
        },
      },
      additionalProperties: false,
    },
  }),
  Object.freeze({
    name: "sync_facts",
    description:
      "Walk the sealed delta stream from a position already held. Each item carries the event, the entry, its verification class and its attribution.",
    inputSchema: {
      type: "object",
      properties: {
        from: {
          type: "integer",
          description: "The sealed position already held; the stream resumes after it.",
          minimum: 0,
        },
        limit: {
          type: "integer",
          description: "How many events one page asks for.",
          minimum: 1,
        },
        pages: {
          type: "integer",
          description: "How many pages to walk. One by default.",
          minimum: 1,
        },
        domain: { type: "string", description: "A registered domain slug." },
        min_tier: TIER_FILTER,
        min_class: CLASS_FILTER,
      },
      required: ["from"],
      additionalProperties: false,
    },
  }),
  Object.freeze({
    name: "attribution",
    description:
      "Who one entry is owed to: its author, the validators that decided it, anyone who reconfirmed it, and the citation line.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string", description: "An entry id." } },
      required: ["id"],
      additionalProperties: false,
    },
  }),
  Object.freeze({
    name: "verify_bundle",
    description:
      "Check an exported entry against the log bundle beside it, offline, with the record's own verifier. Two local file paths in, one report out.",
    inputSchema: {
      type: "object",
      properties: {
        entry_path: { type: "string", description: "Path to entry.json." },
        log_path: { type: "string", description: "Path to log.json." },
      },
      required: ["entry_path", "log_path"],
      additionalProperties: false,
    },
  }),
  Object.freeze({
    name: "confirm_line",
    description:
      "Check an entry's cited source and compose the public confirmation line for a venue. Nothing is posted, and no key is held here: a venue that binds a key through a profile gets the line unsigned, to be signed with `npm run confirm`.",
    inputSchema: {
      type: "object",
      properties: {
        entry_id: { type: "string", description: "An entry id." },
        venue: {
          type: "string",
          description: "The venue the line is for: 1f916, colony or github.",
        },
        verdict: {
          type: "string",
          description:
            "approve or reject. Omit to let the check decide, which is the ordinary case.",
        },
        check: {
          type: "string",
          description:
            "hash (the default), span-present or span-absent.",
        },
        attest: {
          type: "boolean",
          description:
            "Carry the independence attestation token, registering as a community operator in the same line.",
        },
        reason: {
          type: "string",
          description: "One public sentence. It may not contain an email address.",
        },
      },
      required: ["entry_id", "venue"],
      additionalProperties: false,
    },
  }),
]);

/** What the server needs to answer: a reader, and a fetcher for the checks. */
export interface McpDeps {
  readonly reader: Reader;
  readonly fetcher?: SnapshotFetcher;
}

/** A JSON-RPC response, or null for a notification, which is answered with none. */
export type McpAnswer = Record<string, unknown> | null;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The params object, or an empty one: a missing `params` is an empty params. */
function paramsOf(message: Record<string, unknown>): Record<string, unknown> {
  const params = message["params"];
  return isRecord(params) ? params : {};
}

/**
 * An argument that is not what the tool's schema says it is.
 *
 * Its own class because its answer is its own: a tool that refused is a `-1`
 * for the agent to read and act on, but an argument of the wrong shape is a
 * caller that did not send what it published, and JSON-RPC has a code for that.
 * Raised before any door is read and before the composer is entered, so a bad
 * word never becomes a line, a fetch or a file.
 */
export class InvalidParams extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidParams";
  }
}

/**
 * One argument, read and narrowed.
 *
 * Every reader here refuses rather than defaults: a value of the wrong type is
 * not an absent value, and answering a caller who sent `id: 7` as if they had
 * sent none would be answering a question they did not ask. A cast would pass
 * the compiler and let the same value through, which is the bug these exist to
 * make impossible.
 */
function optionalString(
  params: Record<string, unknown>,
  name: string,
): string | null {
  const value = params[name];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value === "") {
    throw new InvalidParams(`${name} must be a non-empty string`);
  }
  return value;
}

function requiredString(
  params: Record<string, unknown>,
  name: string,
): string {
  const value = optionalString(params, name);
  if (value === null) throw new InvalidParams(`${name} is required`);
  return value;
}

function optionalInteger(
  params: Record<string, unknown>,
  name: string,
  least: number,
): number | null {
  const value = params[name];
  if (value === undefined || value === null) return null;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < least) {
    throw new InvalidParams(`${name} must be an integer of at least ${least}`);
  }
  return value;
}

function requiredInteger(
  params: Record<string, unknown>,
  name: string,
  least: number,
): number {
  const value = optionalInteger(params, name, least);
  if (value === null) throw new InvalidParams(`${name} is required`);
  return value;
}

function optionalBoolean(
  params: Record<string, unknown>,
  name: string,
): boolean {
  const value = params[name];
  if (value === undefined || value === null) return false;
  if (typeof value !== "boolean") {
    throw new InvalidParams(`${name} must be true or false`);
  }
  return value;
}

/** One argument narrowed by a guard, or the invalid-params refusal. */
function optionalWord<T>(
  params: Record<string, unknown>,
  name: string,
  is: (value: unknown) => value is T,
  allowed: readonly string[],
): T | null {
  const value = params[name];
  if (value === undefined || value === null) return null;
  if (!is(value)) {
    throw new InvalidParams(`${name} must be one of: ${allowed.join(", ")}`);
  }
  return value;
}

function requiredWord<T>(
  params: Record<string, unknown>,
  name: string,
  is: (value: unknown) => value is T,
  allowed: readonly string[],
): T {
  const value = optionalWord(params, name, is, allowed);
  if (value === null) throw new InvalidParams(`${name} is required`);
  return value;
}

function result(id: unknown, value: Record<string, unknown>): McpAnswer {
  return { jsonrpc: "2.0", id, result: value };
}

function failure(id: unknown, code: number, message: string): McpAnswer {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

/** One tool answer: the lines a reader wants, then the JSON an agent wants. */
function content(lines: readonly string[], data: unknown): Record<string, unknown> {
  return {
    content: [
      {
        type: "text",
        text: `${lines.join("\n")}\n\n${JSON.stringify(data, null, 2)}`,
      },
    ],
  };
}

/** A tool that refused: an error to the caller, never to the protocol. */
function toolError(message: string): Record<string, unknown> {
  return {
    content: [{ type: "text", text: message }],
    isError: true,
  };
}

/** A short cause, one line, never a stack. */
function reasonOf(error: unknown): string {
  if (error instanceof ConfirmRefused) return error.message;
  if (error instanceof Error) {
    const first = error.message.split("\n")[0];
    if (first !== undefined && first.length > 0) return first;
  }
  return "unknown error";
}

/** The header lines every fact answers with, in the order a reader reads them. */
function factLines(input: {
  claim: unknown;
  status: string | null;
  verification_class: string | null;
  effective_tier: string | null;
  citation: string | null;
}): string[] {
  return [
    `fact: ${typeof input.claim === "string" ? input.claim : "(no claim)"}`,
    `status: ${input.status ?? "unknown"}`,
    `verification class: ${input.verification_class ?? "none"}`,
    `evidence tier: ${input.effective_tier ?? "none"}`,
    `cite: ${input.citation ?? "(no attribution)"}`,
  ];
}

/** One line per stream item, short enough to scan. */
function itemLine(item: SyncItem): string {
  return [
    `seq ${item.seq}`,
    item.kind,
    item.entry_id ?? "-",
    `status ${item.status ?? "-"}`,
    `class ${item.verification_class ?? "-"}`,
  ].join(" ");
}

/** The server: one message in, one answer out, and no state between them. */
export interface McpServer {
  handle(message: unknown): Promise<McpAnswer>;
  /** One line in, one line out, or null when there is nothing to say. */
  handleLine(line: string): Promise<string | null>;
}

export function createMcpServer(deps: McpDeps): McpServer {
  const reader = deps.reader;

  const callTool = async (
    name: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown> | null> => {
    if (name === "read_fact") {
      const id = optionalString(params, "id");
      const subject = optionalString(params, "subject");
      const category = optionalString(params, "category");
      const domain = optionalString(params, "domain");
      const minTier = optionalString(params, "min_tier");
      const minClass = optionalString(params, "min_class");
      const maxAge = optionalInteger(params, "max_age", 0);
      let answer;
      if (id !== null) {
        answer = await reader.read(id);
      } else if (subject !== null && category !== null) {
        answer = await reader.read({
          subject,
          category,
          ...(domain === null ? {} : { domain }),
          ...(minTier === null ? {} : { min_tier: minTier }),
          ...(minClass === null ? {} : { min_class: minClass }),
          ...(maxAge === null ? {} : { max_age: maxAge }),
        });
      } else {
        throw new InvalidParams(
          "read_fact takes an id, or a subject and a category",
        );
      }
      return content(
        factLines({
          claim: answer.entry["claim"],
          status: answer.status,
          verification_class: answer.verification_class,
          effective_tier: answer.effective_tier,
          citation: answer.citation,
        }),
        {
          entry: answer.entry,
          status: answer.status,
          verification_class: answer.verification_class,
          effective_tier: answer.effective_tier,
          attribution: answer.attribution,
        },
      );
    }

    if (name === "sync_facts") {
      const from = requiredInteger(params, "from", 0);
      const limit = optionalInteger(params, "limit", 1);
      const pages = optionalInteger(params, "pages", 1);
      const domain = optionalString(params, "domain");
      const minTier = optionalString(params, "min_tier");
      const minClass = optionalString(params, "min_class");
      const items: SyncItem[] = [];
      for await (const item of reader.sync({
        from,
        limit: limit ?? 50,
        pages: pages ?? 1,
        ...(domain === null ? {} : { domain }),
        ...(minTier === null ? {} : { min_tier: minTier }),
        ...(minClass === null ? {} : { min_class: minClass }),
      })) {
        items.push(item);
      }
      const head = items.length === 0 ? from : (items[items.length - 1]!.page_head ?? from);
      return content(
        [
          `from ${from}`,
          `head ${head}`,
          `items ${items.length}`,
          ...items.map(itemLine),
        ],
        {
          from,
          head,
          items: items.map((item) => ({
            seq: item.seq,
            kind: item.kind,
            entry_id: item.entry_id,
            status: item.status,
            verification_class: item.verification_class,
            effective_tier: item.effective_tier,
            entry: item.entry,
            attribution: item.attribution,
          })),
        },
      );
    }

    if (name === "attribution") {
      const block = await reader.attribution(requiredString(params, "id"));
      return content([`cite: ${block.citation}`], block);
    }

    if (name === "verify_bundle") {
      const report = await reader.verify(
        requiredString(params, "entry_path"),
        requiredString(params, "log_path"),
      );
      return content(
        [
          report.ok ? "ok" : "failed",
          `entry ${report.entry_id ?? "unknown"}`,
          `diffs ${report.diffs.length}`,
          `bundle ${report.bounded ? "bounded" : "full"}`,
          ...(report.not_run.length === 0
            ? []
            : [`not run: ${report.not_run.join(", ")}`]),
        ],
        report,
      );
    }

    if (name === "confirm_line") {
      const entryId = requiredString(params, "entry_id");
      // The venue is narrowed against the policy table itself, so a venue this
      // record does not publish is refused here rather than deep inside the
      // composer, and never after a source has been fetched.
      const venue = requiredWord(
        params,
        "venue",
        isVenueName,
        CONFIRMATION_VENUES.map((row) => row.venue),
      );
      const verdict = optionalWord(params, "verdict", isVerdictWord, [
        "approve",
        "reject",
      ]);
      const check = optionalWord(params, "check", isCheckWord, CHECK_WORDS);
      const prepared = await prepareConfirmation(
        {
          baseUrl: reader.base,
          entryId,
          venue,
          verdict,
          check,
          attest: optionalBoolean(params, "attest"),
          reason: optionalString(params, "reason"),
          // No key reaches an agent's tool call, ever. A venue that binds
          // through a profile gets the line unsigned and the line that says so.
          key: null,
        },
        {
          get: (path: string) => reader.fetchJson(path),
          ...(deps.fetcher === undefined ? {} : { fetcher: deps.fetcher }),
        },
      );
      return content(
        [
          `comment: ${prepared.comment_line}`,
          `canonical: ${prepared.canonical_line}`,
          `verdict: ${prepared.verdict}${prepared.forced ? " (forced)" : ""}`,
          `reproduced: ${prepared.reproduced ? "yes" : "no"}`,
          ...(prepared.fingerprint === null
            ? [
                "signature: none here — sign it with: npm run confirm -- <base> " +
                  `${prepared.entry_id} ${prepared.verdict} --venue ${prepared.venue} --key <key.json>`,
              ]
            : [`fingerprint: ${prepared.fingerprint}`]),
        ],
        prepared,
      );
    }

    return null;
  };

  const handle = async (message: unknown): Promise<McpAnswer> => {
    if (!isRecord(message)) {
      return failure(null, JSONRPC_ERRORS.invalidRequest, "not a JSON-RPC object");
    }
    const method = message["method"];
    const hasId = "id" in message && message["id"] !== null;
    const id = hasId ? message["id"] : null;
    if (typeof method !== "string") {
      return hasId
        ? failure(id, JSONRPC_ERRORS.invalidRequest, "no method")
        : null;
    }

    // A notification carries no id and is answered with nothing at all.
    if (!hasId) return null;

    const params = paramsOf(message);

    if (method === "initialize") {
      const version = params["protocolVersion"];
      const asked =
        typeof version === "string" && version !== "" ? version : null;
      return result(id, {
        protocolVersion: asked ?? DEFAULT_PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: MCP_SERVER_NAME, version: KIT_VERSION },
      });
    }

    if (method === "tools/list") return result(id, { tools: TOOLS });

    if (method === "tools/call") {
      const name = params["name"];
      if (typeof name !== "string" || name === "") {
        return failure(id, JSONRPC_ERRORS.invalidParams, "no tool name");
      }
      const args = params["arguments"];
      try {
        if (args !== undefined && args !== null && !isRecord(args)) {
          throw new InvalidParams("arguments must be an object");
        }
        const answer = await callTool(name, isRecord(args) ? args : {});
        if (answer === null) {
          return failure(
            id,
            JSONRPC_ERRORS.invalidParams,
            `unknown tool: ${name}`,
          );
        }
        return result(id, answer);
      } catch (error) {
        // An argument of the wrong shape is a message that does not match the
        // schema this server published, which is what `-32602` is for. It is
        // raised before any door is read, so nothing was done with it.
        if (error instanceof InvalidParams) {
          return failure(
            id,
            JSONRPC_ERRORS.invalidParams,
            `${name}: ${error.message}`,
          );
        }
        // A door that refused, a source that would not answer, a file that is
        // not there: the caller's problem and not the protocol's, so it comes
        // back as a tool error the agent can read and act on.
        return result(id, toolError(`${name}: ${reasonOf(error)}`));
      }
    }

    return failure(id, JSONRPC_ERRORS.methodNotFound, `unknown method: ${method}`);
  };

  return {
    handle,
    async handleLine(line: string): Promise<string | null> {
      const trimmed = line.trim();
      if (trimmed === "") return null;
      let message: unknown;
      try {
        message = JSON.parse(trimmed);
      } catch {
        // The id is unknowable in a line that would not parse, so it is null,
        // which is what JSON-RPC says to answer. The loop reads the next line.
        return JSON.stringify(
          failure(null, JSONRPC_ERRORS.parse, "invalid JSON"),
        );
      }
      try {
        const answer = await handle(message);
        return answer === null ? null : JSON.stringify(answer);
      } catch (error) {
        return JSON.stringify(
          failure(null, JSONRPC_ERRORS.internal, reasonOf(error)),
        );
      }
    },
  };
}

/**
 * Run the server over a stream of chunks, one message per line.
 *
 * The buffer is split on newlines and never on anything else: a message is one
 * line by the protocol's own framing, and a chunk boundary in the middle of one
 * is the ordinary case rather than an error.
 */
export async function runMcp(
  server: McpServer,
  input: AsyncIterable<string | Uint8Array>,
  write: (line: string) => void,
): Promise<void> {
  const decoder = new TextDecoder();
  let buffer = "";
  for await (const chunk of input) {
    buffer +=
      typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true });
    for (;;) {
      const at = buffer.indexOf("\n");
      if (at < 0) break;
      const line = buffer.slice(0, at);
      buffer = buffer.slice(at + 1);
      const answer = await server.handleLine(line);
      if (answer !== null) write(answer);
    }
  }
  // Whatever was left without a trailing newline is still a message: a client
  // that closed its pipe after the last line has still sent that line.
  const answer = await server.handleLine(buffer);
  if (answer !== null) write(answer);
}

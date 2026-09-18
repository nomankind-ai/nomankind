/**
 * The reader kit's client: everything a stranger needs to read this record, and
 * no key anywhere in it.
 *
 * Whitepaper, The training path: a learner is handed "the frozen reader" — one
 * fact at a time, with a receipt — and "the delta stream", the sealed log after
 * a position they already hold. Decision D-131 item 4 says the kit needs no
 * key, and decision D-127 item 4b says every fact travels with who signed it.
 * Both are the whole shape of this file: every read is unauthenticated, and
 * every answer carries the entry's attribution block beside the entry, with the
 * citation line a reader pastes under the fact.
 *
 * Four doors and nothing else, all public:
 *
 *   GET /read/{id}                  one verified fact, with its sidecar
 *   GET /entries/{id}               the entry itself, at any status
 *   GET /entries/{id}/attribution   who it is owed to (D-130)
 *   GET /read?subject=…             one fact by subject and category
 *   GET /sync?from=…                the delta stream, paged
 *
 * `read(id)` asks the frozen reader first, because that door is the one that
 * carries the sidecar — the effective tier and the verification class, which is
 * who met the entry's consensus (D-138) — and falls back to the entry door when
 * the reader is 409 `entry_not_verified`. A draft is a real answer with a real
 * status, and a kit that could only show verified facts would be a kit that
 * could not show a reader what a draft looks like.
 *
 * Nothing here decides anything. The status, the tier and the class are read
 * off what the doors answered; the verification is the kernel's
 * (`verifyOffline`); the citation line is `attributionOf`'s. This file is the
 * shape of the requests and nothing more.
 *
 * node:fs reaches this file through `exportBundle` alone, which writes the same
 * three files `npm run export` writes by calling that command's own functions —
 * one implementation of the bundle, so a kit user and a maintainer check the
 * same bytes.
 */

import type { Attribution } from "../attribution.js";
import { buildExport, writeExport } from "../cli/export.js";
import type { HttpClient } from "../cli/validator.js";
import { verifyOffline, type VerifyReport } from "../verify.js";

/** What the kit calls itself on the wire. */
export const KIT_NAME = "nomankind-reader-kit";

/**
 * The kit's own version, which is not the record's.
 *
 * A client names itself so an operator reading a log can tell one reader from
 * another, and so a WAF has something to allow that is not "a stock runtime's
 * default". It moves when the kit's wire behaviour moves and not when the
 * record does.
 */
export const KIT_VERSION = "1.0.0";

/** The User-Agent every request carries unless the caller names another. */
export const KIT_USER_AGENT = `${KIT_NAME}/${KIT_VERSION} (+https://nomankind.ai/docs)`;

/** Somewhere to send a request: the platform's fetch, or a test's stand-in. */
export type KitFetch = (request: Request) => Promise<Response>;

/** What a reader is pointed at, and what it calls itself. */
export interface ReaderOptions {
  /** The base URL, e.g. `https://app.nomankind.ai`. */
  readonly base: string;
  readonly fetch?: KitFetch;
  readonly userAgent?: string;
}

/**
 * A door that refused, in the door's own word.
 *
 * The status and the record's own error word are kept apart from the message,
 * so a caller branches on `reason` rather than on prose.
 */
export class ReaderRefusal extends Error {
  readonly status: number;
  readonly reason: string;
  readonly path: string;

  constructor(path: string, status: number, reason: string) {
    super(`${path}: refused ${status} ${reason}`);
    this.name = "ReaderRefusal";
    this.status = status;
    this.reason = reason;
    this.path = path;
  }
}

/** One fact, and everyone it is owed to. */
export interface ReadAnswer {
  readonly entry: Record<string, unknown>;
  readonly entry_id: string;
  readonly status: string | null;
  /** Off the sidecar, and null on the entry door, which carries none. */
  readonly effective_tier: string | null;
  /** Who met the consensus (D-138), off the sidecar; null without one. */
  readonly verification_class: string | null;
  /** Null only when the attribution door refused with a 404. */
  readonly attribution: Attribution | null;
  /** The one line a reader pastes under the fact, or null with no block. */
  readonly citation: string | null;
  /** True when the frozen reader answered, false on the entry-door fallback. */
  readonly receipted: boolean;
}

/** A fact asked for by what it is about rather than by its id. */
export interface ReadQuery {
  readonly subject: string;
  readonly category: string;
  readonly domain?: string;
  readonly min_tier?: string;
  readonly min_class?: string;
  readonly max_age?: number | string;
}

/** What the delta stream is asked for. */
export interface SyncRequest {
  readonly from: number;
  readonly limit: number;
  readonly domain?: string;
  readonly min_tier?: string;
  readonly min_class?: string;
  /**
   * How many pages to walk before stopping, or absent for the whole stream.
   *
   * A bound rather than a filter: a caller that wants one page asks for one,
   * and a caller replaying the log asks for none and gets every page until the
   * door stops advancing the head.
   */
  readonly pages?: number;
}

/** One item of the stream, with the state the item's entry stood in. */
export interface SyncItem {
  readonly seq: number;
  readonly kind: string;
  readonly event: Record<string, unknown>;
  readonly entry: Record<string, unknown> | null;
  readonly entry_id: string | null;
  readonly sidecar: Record<string, unknown> | null;
  readonly status: string | null;
  readonly effective_tier: string | null;
  readonly verification_class: string | null;
  /** The entry's own block, on every item that is about an entry. */
  readonly attribution: Attribution | null;
  readonly citation: string | null;
  /** Where the page this item came from left the stream. */
  readonly page_head: number | null;
}

/** Where the export's three files landed. */
export interface ExportedBundle {
  readonly entryPath: string;
  readonly bundlePath: string;
  readonly attributionPath: string;
}

/** The kit's whole surface. */
export interface Reader {
  read(target: string | ReadQuery): Promise<ReadAnswer>;
  sync(request: SyncRequest): AsyncGenerator<SyncItem, void, undefined>;
  attribution(id: string): Promise<Attribution>;
  exportBundle(
    id: string,
    dir: string,
    options?: { readonly bounded?: boolean },
  ): Promise<ExportedBundle>;
  verify(entryPath: string, logPath: string): Promise<VerifyReport>;
  cite(attribution: Attribution | null): string;
  /**
   * One GET against the base, with its status and body, for a caller that
   * needs a door this surface does not wrap — the confirm command's read of
   * the entry itself, which wants a 404 as an answer rather than as a throw.
   */
  fetchJson(path: string): Promise<{ status: number; body: unknown }>;
  /** The base every door above is read from, for a caller that prints it. */
  readonly base: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A string field, or null when the object carries none. */
function text(value: unknown, name: string): string | null {
  if (!isRecord(value)) return null;
  const field = value[name];
  return typeof field === "string" ? field : null;
}

/** The record's own error word out of a refusal body, or `unknown`. */
function errorWord(body: unknown): string {
  return text(body, "error") ?? "unknown";
}

/**
 * The attribution block a door answered, or null when it is not one.
 *
 * Shape-checked rather than cast: the block travels on the sync stream beside
 * entries a stranger's deployment served, and a caller that printed
 * `undefined.citation` would be a kit that crashed on somebody else's bytes.
 */
function asAttribution(value: unknown): Attribution | null {
  if (!isRecord(value)) return null;
  if (!isRecord(value["author"])) return null;
  if (!Array.isArray(value["validators"])) return null;
  if (typeof value["citation"] !== "string") return null;
  return value as unknown as Attribution;
}

/**
 * A reader over the public doors, holding no key and signing nothing.
 *
 * The User-Agent is set on every request and names the kit and its version. A
 * stock runtime's default agent is what a WAF has to guess about; a client that
 * says what it is can be allowed or refused on purpose.
 */
export function createReader(options: ReaderOptions): Reader {
  const base = options.base;
  const send: KitFetch =
    options.fetch ??
    ((request: Request): Promise<Response> => globalThis.fetch(request));
  const userAgent = options.userAgent ?? KIT_USER_AGENT;

  const request = (path: string): Request =>
    new Request(new URL(path, base).toString(), {
      method: "GET",
      headers: { "user-agent": userAgent, accept: "application/json" },
    });

  /** One GET, with its status and whatever JSON came back. */
  const get = async (
    path: string,
  ): Promise<{ status: number; body: unknown }> => {
    const response = await send(request(path));
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    return { status: response.status, body };
  };

  /** One GET that must have answered 200, or the door's own refusal. */
  const getOk = async (path: string): Promise<unknown> => {
    const answer = await get(path);
    if (answer.status !== 200) {
      throw new ReaderRefusal(path, answer.status, errorWord(answer.body));
    }
    return answer.body;
  };

  /**
   * The HttpClient the export command takes, over this reader's own fetch.
   *
   * One place the header is added and one path the bytes travel, so a bundle
   * exported through the kit goes out under the kit's own name exactly as a
   * read does.
   */
  const http: HttpClient = {
    async fetch(incoming: Request): Promise<Response> {
      const headers = new Headers(incoming.headers);
      if (!headers.has("user-agent")) headers.set("user-agent", userAgent);
      return send(new Request(incoming, { headers }));
    },
  };

  const attribution = async (id: string): Promise<Attribution> => {
    const path = `/entries/${encodeURIComponent(id)}/attribution`;
    const block = asAttribution(await getOk(path));
    if (block === null) throw new ReaderRefusal(path, 200, "bad_attribution");
    return block;
  };

  /** The block, or null when the door has none for this entry. */
  const attributionOrNull = async (id: string): Promise<Attribution | null> => {
    try {
      return await attribution(id);
    } catch (error) {
      if (error instanceof ReaderRefusal && error.status === 404) return null;
      throw error;
    }
  };

  /** One answer built out of whichever door served the entry. */
  const answerFor = async (
    entry: Record<string, unknown>,
    sidecar: Record<string, unknown> | null,
    receipted: boolean,
  ): Promise<ReadAnswer> => {
    const entryId = text(entry, "id");
    if (entryId === null) {
      throw new ReaderRefusal("/read", 200, "entry_without_id");
    }
    const block = await attributionOrNull(entryId);
    return {
      entry,
      entry_id: entryId,
      status: text(entry, "status"),
      effective_tier: text(sidecar, "effective_tier"),
      verification_class: text(sidecar, "verification_class"),
      attribution: block,
      citation: block === null ? null : block.citation,
      receipted,
    };
  };

  const readById = async (id: string): Promise<ReadAnswer> => {
    const reader = await get(`/read/${encodeURIComponent(id)}`);
    if (reader.status === 200 && isRecord(reader.body)) {
      const entry = reader.body["entry"];
      if (isRecord(entry)) {
        const sidecar = reader.body["sidecar"];
        return answerFor(entry, isRecord(sidecar) ? sidecar : null, true);
      }
    }
    // A fact the frozen reader will not serve is still a fact this record
    // holds: 409 `entry_not_verified` is a draft, a rejection or a superseded
    // entry, and the entry door answers every one of them (D-127). Anything
    // else — a 404, a rate limit — is the reader's refusal and is raised as it
    // was given, because falling back from those would hide them.
    if (reader.status !== 409) {
      const path = `/read/${encodeURIComponent(id)}`;
      throw new ReaderRefusal(path, reader.status, errorWord(reader.body));
    }
    const entry = await getOk(`/entries/${encodeURIComponent(id)}`);
    if (!isRecord(entry)) {
      throw new ReaderRefusal(
        `/entries/${encodeURIComponent(id)}`,
        200,
        "not_an_entry",
      );
    }
    return answerFor(entry, null, false);
  };

  const readByQuery = async (query: ReadQuery): Promise<ReadAnswer> => {
    const params = new URLSearchParams();
    params.set("subject", query.subject);
    params.set("category", query.category);
    if (query.domain !== undefined) params.set("domain", query.domain);
    if (query.min_tier !== undefined) params.set("min_tier", query.min_tier);
    if (query.min_class !== undefined) params.set("min_class", query.min_class);
    if (query.max_age !== undefined) {
      params.set("max_age", String(query.max_age));
    }
    const body = await getOk(`/read?${params.toString()}`);
    const entry = isRecord(body) ? body["entry"] : null;
    if (!isRecord(entry)) {
      throw new ReaderRefusal("/read", 200, "not_an_entry");
    }
    const sidecar = isRecord(body) ? body["sidecar"] : null;
    return answerFor(entry, isRecord(sidecar) ? sidecar : null, true);
  };

  async function* sync(
    input: SyncRequest,
  ): AsyncGenerator<SyncItem, void, undefined> {
    let from = input.from;
    let walked = 0;
    for (;;) {
      if (input.pages !== undefined && walked >= input.pages) return;
      const params = new URLSearchParams();
      params.set("from", String(from));
      params.set("limit", String(input.limit));
      if (input.domain !== undefined) params.set("domain", input.domain);
      if (input.min_tier !== undefined) params.set("min_tier", input.min_tier);
      if (input.min_class !== undefined) {
        params.set("min_class", input.min_class);
      }
      const body = await getOk(`/sync?${params.toString()}`);
      walked += 1;
      if (!isRecord(body)) return;
      const events = body["events"];
      const head = typeof body["head"] === "number" ? body["head"] : null;
      if (!Array.isArray(events) || events.length === 0) return;

      for (const raw of events) {
        if (!isRecord(raw)) continue;
        const event = isRecord(raw["event"]) ? raw["event"] : {};
        const entry = isRecord(raw["entry"]) ? raw["entry"] : null;
        const sidecar = isRecord(raw["sidecar"]) ? raw["sidecar"] : null;
        const block = asAttribution(raw["attribution"]);
        yield {
          seq: typeof raw["seq"] === "number" ? raw["seq"] : -1,
          kind: text(raw, "kind") ?? "unknown",
          event,
          entry,
          entry_id: text(entry, "id") ?? text(event, "entry_id"),
          sidecar,
          status: text(entry, "status"),
          effective_tier: text(sidecar, "effective_tier"),
          verification_class: text(sidecar, "verification_class"),
          attribution: block,
          citation: block === null ? null : block.citation,
          page_head: head,
        };
      }

      // The head is where this page left the stream, and the next page resumes
      // strictly after it. A head that did not advance is a door that has
      // nothing more to say; walking again would be an endless loop over the
      // same page, which is the one failure a pager owes a caller not to have.
      if (head === null || head <= from) return;
      from = head;
    }
  }

  return {
    base,
    read: (target: string | ReadQuery): Promise<ReadAnswer> =>
      typeof target === "string" ? readById(target) : readByQuery(target),
    sync,
    attribution,
    fetchJson: get,
    async exportBundle(
      id: string,
      dir: string,
      exportOptions?: { readonly bounded?: boolean },
    ): Promise<ExportedBundle> {
      const result = await buildExport({
        baseUrl: base,
        entryId: id,
        http,
        now: new Date(),
        ...(exportOptions?.bounded === true ? { bounded: true } : {}),
      });
      return writeExport(dir, result);
    },
    async verify(entryPath: string, logPath: string): Promise<VerifyReport> {
      const { readFile } = await import("node:fs/promises");
      const entry: unknown = JSON.parse(await readFile(entryPath, "utf8"));
      const bundle: unknown = JSON.parse(await readFile(logPath, "utf8"));
      return verifyOffline(entry, bundle);
    },
    /**
     * The one line a reader pastes under a fact: the record's own citation.
     *
     * "Cite the validator" (D-127 item 4b) is a sentence about who is named,
     * and the block already names them — the subject, the category, the
     * validators that met the consensus, the entry id and the sealed position.
     * This is that line and never a second spelling of it.
     */
    cite(block: Attribution | null): string {
      return block === null ? "(no attribution)" : block.citation;
    },
  };
}

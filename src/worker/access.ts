/**
 * The tier gate.
 *
 * Whitepaper Section 9, Money: "The log is free to read at low volume, forever.
 * Revenue comes from high-rate API access, structured feeds and webhooks,
 * change alerts." This is where that sentence is enforced, and it is the whole
 * of it: a request with no key is served on the free tier, a request with a key
 * is served on the key's, and both are counted against a cap per UTC day.
 *
 * Every reading door calls `resolveAccess` first and `chargeReads` after it has
 * served. The order matters: a reader is charged for what they got, never for
 * what they asked for, so a refusal costs nothing and a door that failed halfway
 * has not billed anybody. It also means a page can overshoot the cap by one
 * page — the delta stream charges the verified entries it delivered, and the
 * last page before the cap may carry more of them than the cap had room for.
 * That is deliberate and documented: the alternative is refusing a page that was
 * already built, or counting before the work, and both are worse than one page
 * of slack at a boundary.
 *
 * Nothing is decided here that src/keys.ts does not decide: the shape of a
 * secret, the three statuses, the scope a reader is counted under and the cap of
 * a tier are all the kernel's. This file gathers the facts in order and refuses
 * in the kernel's own words.
 *
 * No wall clock: `now` is the instant the router read once for the whole
 * request, and the day every count belongs to is that instant's UTC day. No
 * policy number lives here — the bare integers are HTTP status codes and the
 * caps are RATE_TIERS's.
 */

import { utcDay } from "../anchor.js";
import { publicKeyFromAgentId } from "../identity.js";
import { FREE_TIER } from "../policy.js";
import {
  KEY_REFUSALS,
  keyHash,
  looksLikeKey,
  quotaScopeForClient,
  quotaScopeForKey,
  tierLimit,
  type KeyRecord,
} from "../keys.js";
import { HEADER_AGENT, verifyRequest } from "../request.js";
import type { D1Like } from "../storage/d1.js";
import { addQuota, keyByHash, quotaOn } from "../storage/keys.js";
import { D1NonceStore } from "../storage/nonces.js";
import { operatorForAgent } from "../storage/repository.js";
import type { Env } from "./env.js";

/** How many milliseconds a day is. Not a policy number: it is what a day is. */
const MILLISECONDS_PER_DAY = 86_400_000;

/**
 * What a door was granted: the tier, the key behind it or null on the free
 * tier, the scope the reads are counted under, the day they are counted on, the
 * cap and what has been used before this request.
 */
export interface Access {
  readonly tier: string;
  readonly key: KeyRecord | null;
  readonly scope: string;
  /** The UTC day of `now`, captured so the charge lands on the day of the read. */
  readonly day: string;
  readonly limit: number;
  readonly used: number;
}

/** A refusal from the gate, in the status and the word the door answers with. */
export type AccessRefusal = {
  readonly status: 401 | 402 | 429;
  readonly reason: (typeof KEY_REFUSALS)[number];
  readonly body: Record<string, unknown>;
  /** Seconds until the cap resets, on a rate refusal only. */
  readonly retryAfter?: number;
};

function refusal(
  status: 401 | 402,
  reason: (typeof KEY_REFUSALS)[number],
): { ok: false; refusal: AccessRefusal } {
  return { ok: false, refusal: { status, reason, body: { error: reason } } };
}

/** The start of the day after this one, which is when a cap resets. */
function resetsAt(day: string): string {
  const start = Date.parse(`${day}T00:00:00.000Z`);
  return new Date(start + MILLISECONDS_PER_DAY).toISOString();
}

/** The bearer secret on a request, or null when the header names none. */
function bearer(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (header === null) return null;
  const PREFIX = "bearer ";
  if (!header.toLowerCase().startsWith(PREFIX)) return header.trim();
  return header.slice(PREFIX.length).trim();
}

/**
 * Who is asking, on what tier, and whether they have anything left today.
 *
 * In order, and the order is the contract: no header at all is the free tier, a
 * header that is not a well-formed key is refused before the database is
 * touched, an unknown key is refused before the quota is read, and a key whose
 * subscription is not paid is refused before anything is counted. A reader who
 * mistyped their key is told which rule refused them rather than "unauthorized".
 */
export async function resolveAccess(
  db: D1Like,
  request: Request,
  now: Date,
): Promise<{ ok: true; access: Access } | { ok: false; refusal: AccessRefusal }> {
  const day = utcDay(now.toISOString());
  const presented = bearer(request);

  let key: KeyRecord | null = null;
  let tier = FREE_TIER;
  if (presented !== null) {
    if (!looksLikeKey(presented)) return refusal(401, "bad_key");
    key = await keyByHash(db, await keyHash(presented));
    if (key === null) return refusal(401, "unknown_key");
    if (key.status === "canceled") return refusal(402, "key_canceled");
    if (key.status === "past_due") return refusal(402, "key_past_due");
    tier = key.tier;
  }

  const scope =
    key === null
      ? await quotaScopeForClient(request.headers.get("cf-connecting-ip"))
      : quotaScopeForKey(key.id);
  const limit = tierLimit(tier);
  const used = await quotaOn(db, scope, day);

  if (used >= limit) {
    const resets = resetsAt(day);
    return {
      ok: false,
      refusal: {
        status: 429,
        reason: "rate_limited",
        body: {
          error: "rate_limited",
          tier,
          limit,
          used,
          resets_at: resets,
        },
        retryAfter: Math.max(
          1,
          Math.ceil((Date.parse(resets) - now.getTime()) / 1000),
        ),
      },
    };
  }

  return { ok: true, access: { tier, key, scope, day, limit, used } };
}

/**
 * Charge what was served.
 *
 * The day comes from the access the gate resolved and not from a clock read
 * here, so a request that straddles midnight is counted on the day it was let
 * in on — the same day its cap was checked against. Zero charges nothing: a
 * sync page that delivered no verified entry delivered no read.
 */
export async function chargeReads(
  db: D1Like,
  access: Access,
  reads: number,
): Promise<void> {
  if (reads <= 0) return;
  await addQuota(db, access.scope, access.day, reads);
}

/**
 * The next number on one key's own receipt counter.
 *
 * `UPDATE ... RETURNING` so the read and the write are one statement: two
 * isolates serving the same key at the same instant get different numbers
 * because the database hands them out, exactly as the log-wide counter's unique
 * index makes the second writer try again. The partial unique index on
 * (key_id, key_counter) is still there as the second guard.
 */
export async function nextKeyCounter(
  db: D1Like,
  keyId: string,
): Promise<number> {
  const row = await db
    .prepare(
      `UPDATE api_keys SET counter = counter + 1 WHERE id = ? RETURNING counter`,
    )
    .bind(keyId)
    .first<Record<string, unknown>>();
  const counter = row === null ? null : row["counter"];
  if (typeof counter !== "number" || !Number.isInteger(counter)) {
    throw new TypeError(`nextKeyCounter: no counter for ${keyId}`);
  }
  return counter;
}

/**
 * What every served response says about the reader's day: the tier, the cap,
 * and what is left after this response.
 *
 * Three headers and not a body field, because a reader who wants them wants
 * them on every response including the ones they did not parse, and because a
 * body field would have to go inside the signed receipt or be a second place
 * the same number is written.
 */
export function accessHeaders(
  access: Access,
  remainingAfter: number,
): Record<string, string> {
  return {
    "x-nomankind-tier": access.tier,
    "x-nomankind-limit": String(access.limit),
    "x-nomankind-remaining": String(Math.max(0, remainingAfter)),
  };
}

// ---------------------------------------------------------------------------
// The release window's reader (decision D-100)
// ---------------------------------------------------------------------------

/**
 * Who is reading, for the one question the release window asks: may this
 * request see content that has not been released yet?
 *
 * Three answers and no fourth. `key` is a valid active bearer key, resolved by
 * `resolveAccess` above and by nothing else, so a paid reader is the same reader
 * at every door and is metered the same way. `operator` is a request carrying
 * the M2 signed-request headers (D-014) from an agent bound to a registered
 * operator -- any operator, exactly as the M24c disclosure gate decides it,
 * because the people who have to reproduce an observation are the validators.
 * `free` is everybody else.
 *
 * A bad key or a bad signature is never quietly downgraded to free: a reader who
 * mistyped their key is refused in the gate's own words, and a signature that
 * does not verify is `bad_signature` rather than a free read that silently
 * showed them less than they asked for.
 */
export type ReaderAccess =
  | { readonly kind: "key"; readonly key: Access }
  | { readonly kind: "operator"; readonly operator: string; readonly agent: string }
  | { readonly kind: "free" };

/**
 * What a reader can be refused with: the key gate's own refusals, and the one
 * this gate adds.
 *
 * `bad_signature` is 401 and never a free read. A request that carried no agent
 * header asked for nothing and is free; a request that presented a signature
 * which does not verify asked for something and must be told it did not get it,
 * for the same reason a mistyped key is `bad_key` rather than a quiet
 * downgrade. An agent whose signature verifies but who is bound to no registered
 * operator is neither: they proved who they are and are simply not entitled, so
 * they read free.
 */
export type ReaderRefusal =
  | AccessRefusal
  | {
      readonly status: 401;
      readonly reason: "bad_signature";
      readonly body: Record<string, unknown>;
    };

/**
 * The four M2 headers off a request, lowercased, as `verifyRequest` reads them.
 */
function headersOf(request: Request): Record<string, string> {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });
  return headers;
}

/**
 * The operator behind a signed GET, or null when the request carries no valid
 * signature or the key belongs to nobody registered.
 *
 * Exactly the form the M24c disclosure gate verifies (src/worker/submit.ts):
 * method `GET`, the request's own `pathname` with no query string, a null body,
 * the four headers, and the nonce store pruned at the injected clock. One form,
 * so a command that can sign for the disclosure gate can sign for this one.
 */
async function signedOperator(
  request: Request,
  env: Env,
  now: Date,
): Promise<{ operator: string; agent: string } | null | "bad_signature"> {
  const headers = headersOf(request);
  const agentHeader = headers[HEADER_AGENT];
  if (agentHeader === undefined || agentHeader === "") return null;

  let publicKey: Uint8Array;
  try {
    publicKey = publicKeyFromAgentId(agentHeader);
  } catch {
    return "bad_signature";
  }

  const nonces = new D1NonceStore(env.DB);
  await nonces.prune(now);
  const verdict = await verifyRequest({
    method: request.method,
    path: new URL(request.url).pathname,
    body: null,
    headers,
    publicKey,
    now,
    nonces,
  });
  if (!verdict.ok) return "bad_signature";
  const operator = await operatorForAgent(env.DB, verdict.agentId);
  return operator === null ? null : { operator, agent: verdict.agentId };
}

/**
 * The reader behind one request, resolved once per request.
 *
 * The key first, because a key is the cheaper and the commoner answer and
 * because its refusals are the ones a reader has paid to be told; then the
 * signature, which costs a nonce write; then free. Every door the window touches
 * calls this exactly once and passes the answer down, so two checks in one
 * request can never disagree about who is asking.
 */
export async function readerAccess(
  request: Request,
  env: Env,
  db: D1Like,
  now: Date,
): Promise<
  { ok: true; reader: ReaderAccess } | { ok: false; refusal: ReaderRefusal }
> {
  const resolved = await resolveAccess(db, request, now);
  if (!resolved.ok) return resolved;
  if (resolved.access.key !== null) {
    return { ok: true, reader: { kind: "key", key: resolved.access } };
  }

  const signed = await signedOperator(request, env, now);
  if (signed === "bad_signature") {
    return {
      ok: false,
      refusal: {
        status: 401,
        reason: "bad_signature",
        body: { error: "bad_signature" },
      },
    };
  }
  if (signed !== null) {
    return {
      ok: true,
      reader: { kind: "operator", operator: signed.operator, agent: signed.agent },
    };
  }
  return { ok: true, reader: { kind: "free" } };
}

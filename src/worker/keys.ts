/**
 * The key doors: what a reader who wants a name of their own knocks on.
 *
 * Decision D-127, "the record is free, no money anywhere": a key is not bought
 * any more, it is asked for. Nothing about it is priced, nothing about it is
 * sold, and the caps it carries are caps and never products — what a key buys
 * is an identity the log can count under, so a reader can hold alerts, read
 * their own receipts by counter, and see what they read day by day. Five doors:
 * what the tiers allow, take a key, what my key is, what my key read, and the
 * receipts behind that. The four the paid loop had are gone, addresses and
 * all, so they fall through to the Worker's own 404.
 *
 * One key per client per UTC day, which is the whole of what stands between a
 * free identity and an identity factory. The client is the same per-client
 * identity the write doors count a submission under (src/keys.ts,
 * `quotaScopeForClient`): the address, hashed, or the one anonymous bucket when
 * the platform gave us no address. Nothing here records who asked — the hash is
 * what the row carries, exactly as the read counters do.
 *
 * The secret is shown exactly once, at the door that mints it. There is no door
 * that shows it again, and there is no row anywhere that could: the table holds
 * its hash (src/keys.ts). A reader who loses a key comes back tomorrow, which is
 * the honest consequence of not storing credentials.
 *
 * Nothing is decided here. What a tier allows is src/policy.ts's, what a key is
 * and how one is minted is src/keys.ts's, and the store is query-shaped
 * (src/storage/keys.ts). No wall clock: `deps.now` is the instant the router
 * read once. No policy number lives here — the bare integers are HTTP status
 * codes, and the usage window's default and cap are the two named constants
 * below, which are page sizes of this door and not published amounts.
 */

import {
  keyHash,
  looksLikeKey,
  mintKey,
  quotaScopeForClient,
  quotaScopeForKey,
  tierLimit,
  type KeyRecord,
} from "../keys.js";
import {
  LIST_PAGE_LIMIT,
  RATE_TIERS,
  USAGE_DAYS_DEFAULT,
  USAGE_DAYS_MAX,
} from "../policy.js";
import { utcDay } from "../anchor.js";
import type { D1Like } from "../storage/d1.js";
import {
  KeyDayConflictError,
  keyByClientDay,
  keyByHash,
  putKey,
  quotaDays,
  quotaOn,
  readCountEventOn,
  receiptsForKey,
} from "../storage/keys.js";
import type { Env } from "./env.js";
import {
  guardDatabase,
  isRead,
  json,
  methodNotAllowed,
  READ_METHODS,
  readCappedBody,
  refuse,
  StorageUnreachable,
} from "./registry.js";

/** What the deps these doors take: the instant, and nothing else. */
export interface KeysDeps {
  readonly now: Date;
}

/** How many milliseconds a day is. Not a policy number: it is what a day is. */
const MILLISECONDS_PER_DAY = 86_400_000;

/**
 * The key a request presented, or the refusal it earned.
 *
 * The identity checks only, and deliberately not the quota: these are a
 * holder's own account doors, not reading doors. A key at its daily cap must
 * still be able to see that it is at its cap. The read and sync doors are where
 * a cap decides anything, through `resolveAccess`.
 */
async function keyOf(
  db: D1Like,
  request: Request,
): Promise<{ ok: true; key: KeyRecord } | { ok: false; response: Response }> {
  const header = request.headers.get("authorization");
  if (header === null) {
    return { ok: false, response: refuse(401, "missing_key") };
  }
  // `Bearer <key>` and nothing else (RFC 7235). A header with another scheme, or
  // with no scheme at all, is `bad_key` rather than read as a bare secret: one
  // documented wire format, the same at every door that takes a key.
  const PREFIX = "bearer ";
  if (!header.toLowerCase().startsWith(PREFIX)) {
    return { ok: false, response: refuse(401, "bad_key") };
  }
  const presented = header.slice(PREFIX.length).trim();
  if (!looksLikeKey(presented)) {
    return { ok: false, response: refuse(401, "bad_key") };
  }
  const key = await keyByHash(db, await keyHash(presented));
  if (key === null) {
    return { ok: false, response: refuse(401, "unknown_key") };
  }
  return { ok: true, key };
}

// ---------------------------------------------------------------------------
// The reads
// ---------------------------------------------------------------------------

/**
 * What a tier allows, straight out of policy — and nothing else.
 *
 * A cap and a name per tier, with no price beside it and no share underneath
 * it (D-127): the caps stay as caps, and a tier is what a reader may read in a
 * day rather than something anyone is charged for.
 */
function tiers(): Response {
  return json({ tiers: RATE_TIERS }, 200);
}

/** One key, as its holder sees it: never the hash, never the secret. */
async function me(db: D1Like, key: KeyRecord, now: Date): Promise<Response> {
  const day = utcDay(now.toISOString());
  const used = await quotaOn(db, quotaScopeForKey(key.id), day);
  const limit = tierLimit(key.tier);
  return json(
    {
      id: key.id,
      tier: key.tier,
      status: key.status,
      created_at: key.created_at,
      limit,
      used_today: used,
      remaining_today: Math.max(0, limit - used),
      counter: key.counter,
    },
    200,
  );
}

/**
 * What the key read, day by day, beside what the log published about it.
 *
 * Two numbers per day on purpose. `reads` is this Worker's own counter, which is
 * what the cap was enforced against; `published` is what the sealed `read_count`
 * event for that day says the key read, which is what the ledger priced. A
 * reader comparing the two is doing exactly what Section 9 asks readers to do —
 * "any reader can compare the receipts they hold against the published counts" —
 * and a day where they disagree is a day to ask about.
 *
 * `published` is null while no event has been published for that day yet, and
 * `{ reads: 0, seq }` when the event exists and names no reads for this key:
 * "the log says you read nothing that day" and "the log has not spoken yet" are
 * different answers and must not share a shape.
 */
async function usage(
  db: D1Like,
  key: KeyRecord,
  url: URL,
  now: Date,
): Promise<Response> {
  const requested = url.searchParams.get("days");
  let days = USAGE_DAYS_DEFAULT;
  if (requested !== null) {
    const parsed = Number(requested);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > USAGE_DAYS_MAX) {
      return refuse(400, "bad_days");
    }
    days = parsed;
  }

  const today = utcDay(now.toISOString());
  const from = utcDay(
    new Date(
      Date.parse(`${today}T00:00:00.000Z`) - (days - 1) * MILLISECONDS_PER_DAY,
    ).toISOString(),
  );

  const scope = quotaScopeForKey(key.id);
  const counted = new Map<string, number>();
  for (const row of await quotaDays(db, scope, from, today)) {
    counted.set(row.day, row.reads);
  }

  const out: {
    date: string;
    reads: number;
    published: { reads: number; seq: number } | null;
  }[] = [];
  for (let index = 0; index < days; index += 1) {
    const date = utcDay(
      new Date(
        Date.parse(`${from}T00:00:00.000Z`) + index * MILLISECONDS_PER_DAY,
      ).toISOString(),
    );
    out.push({
      date,
      reads: counted.get(date) ?? 0,
      published: await publishedFor(db, date, key.id),
    });
  }

  return json({ key: key.id, days: out }, 200);
}

/**
 * What the sealed log says one key read on one day.
 *
 * The `paid` block is optional at the type level because the events published
 * before M24 do not carry one, and a day published then names nobody's key:
 * that is `{ reads: 0, seq }`, because the event exists and says this key read
 * nothing.
 */
async function publishedFor(
  db: D1Like,
  date: string,
  keyId: string,
): Promise<{ reads: number; seq: number } | null> {
  const event = await readCountEventOn(db, date);
  if (event === null) return null;
  const payload = event.payload as { paid?: { keys?: Record<string, unknown> } };
  const keys = payload.paid?.keys;
  const count = keys === undefined ? undefined : keys[keyId];
  return {
    reads: typeof count === "number" ? count : 0,
    seq: event.seq,
  };
}

/** A page of the key's own receipts, in the key's own counter order. */
async function receipts(
  db: D1Like,
  key: KeyRecord,
  url: URL,
): Promise<Response> {
  const afterRaw = url.searchParams.get("after");
  let after = 0;
  if (afterRaw !== null) {
    const parsed = Number(afterRaw);
    if (!Number.isInteger(parsed) || parsed < 0) return refuse(400, "bad_after");
    after = parsed;
  }

  const limitRaw = url.searchParams.get("limit");
  let limit = LIST_PAGE_LIMIT;
  if (limitRaw !== null) {
    const parsed = Number(limitRaw);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > LIST_PAGE_LIMIT) {
      return refuse(400, "bad_limit");
    }
    limit = parsed;
  }

  const rows = await receiptsForKey(db, key.id, after, limit);
  return json({ key: key.id, receipts: rows }, 200);
}

// ---------------------------------------------------------------------------
// The free key door, and the four that are gone
// ---------------------------------------------------------------------------

/**
 * The tier a free key is issued at: the first tier in policy that carries a key.
 *
 * Read out of RATE_TIERS rather than written here, so the slug a key is issued
 * under is policy's and not this door's. Null when policy registers no keyed
 * tier at all, which is a refusal rather than a guess: a key minted at a tier
 * that does not exist carries a cap of zero (src/keys.ts, `tierLimit`) and would
 * be a credential that refuses every read it is presented at.
 */
function freeKeyTier(): string | null {
  for (const [slug, tier] of Object.entries(RATE_TIERS)) {
    if (tier.key) return slug;
  }
  return null;
}

/**
 * The part of a client's quota scope that names the client: the hash, or the
 * word every client without an address shares.
 *
 * `quotaScopeForClient` answers `client:<sha256>` or `client:anonymous`, and the
 * prefix is that function's business rather than this column's, so it is taken
 * off before the synthetic values below are built from what is left.
 */
function clientDigest(scope: string): string {
  const PREFIX = "client:";
  return scope.startsWith(PREFIX) ? scope.slice(PREFIX.length) : scope;
}

/**
 * What one client's key for one day is filed under: the client, then the day.
 *
 * The unique index on `client_day` (migrations/0023_money_removed.sql) is what
 * actually enforces one key per client per UTC day. The check below it is the
 * courteous answer; this is the rule, and it holds when two requests race.
 */
function clientDayOf(scope: string, day: string): string {
  return `${clientDigest(scope)}:${day}`;
}

/**
 * POST /keys/free: a key, free, one per client per UTC day.
 *
 * Decision D-127: the record is free and a key is an identity rather than a
 * purchase. So there is nothing to pay, nothing to claim and no provider in the
 * path — the door mints, hashes, stores the hash and hands the secret back once.
 *
 * No body is needed. An empty JSON object is accepted because a client that
 * sends one is being polite rather than wrong, and anything else is `bad_body`:
 * a door that quietly ignored fields would be a door people wrote fields for.
 *
 * The 429 is the one rule this door has. It is answered from the standing row
 * first, for a caller who asks twice, and from the unique index second, for two
 * callers who ask at the same instant — the same pair the claim door used, for
 * the same reason.
 */
async function free(
  request: Request,
  db: D1Like,
  deps: KeysDeps,
): Promise<Response> {
  // The read before the parse, exactly as every other door that takes a body:
  // no door parses a body it has not bounded first.
  const read = await readCappedBody(request);
  if (!read.ok) return read.response;
  if (read.text.trim() !== "") {
    let body: unknown;
    try {
      body = JSON.parse(read.text);
    } catch {
      return refuse(400, "bad_body");
    }
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return refuse(400, "bad_body");
    }
    if (Object.keys(body as Record<string, unknown>).length > 0) {
      return refuse(400, "bad_body");
    }
  }

  const tier = freeKeyTier();
  if (tier === null) return refuse(503, "no_keyed_tier");

  const day = utcDay(deps.now.toISOString());
  const scope = await quotaScopeForClient(request.headers.get("cf-connecting-ip"));
  const clientDay = clientDayOf(scope, day);

  const standing = await keyByClientDay(db, clientDay);
  if (standing !== null) return refuse(429, "key_today");

  const minted = mintKey();
  const at = deps.now.toISOString();
  let stored: KeyRecord;
  try {
    stored = await putKey(db, {
      id: minted.id,
      keyHash: await minted.hash,
      tier,
      // Active from the minute it is minted: there is nothing behind it that
      // could fall due or be cancelled, so the only status a key ever has now
      // is the working one.
      status: "active",
      clientDay,
      createdAt: at,
    });
  } catch (error) {
    if (error instanceof KeyDayConflictError) return refuse(429, "key_today");
    throw error;
  }

  return json(
    {
      // The only time it is shown. The table holds its hash and nothing here
      // can show it again.
      key: minted.secret,
      id: stored.id,
      tier: stored.tier,
      status: stored.status,
      limit: tierLimit(stored.tier),
      created_at: stored.created_at,
    },
    201,
  );
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

async function route(
  request: Request,
  db: D1Like,
  deps: KeysDeps,
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/keys/tiers") {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    return tiers();
  }

  if (path === "/keys/free") {
    if (request.method !== "POST") return methodNotAllowed("POST");
    return free(request, db, deps);
  }

  if (path === "/keys/me") {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    const held = await keyOf(db, request);
    return held.ok ? me(db, held.key, deps.now) : held.response;
  }

  if (path === "/keys/me/usage") {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    const held = await keyOf(db, request);
    return held.ok ? usage(db, held.key, url, deps.now) : held.response;
  }

  if (path === "/keys/me/receipts") {
    if (!isRead(request)) return methodNotAllowed(READ_METHODS);
    const held = await keyOf(db, request);
    return held.ok ? receipts(db, held.key, url) : held.response;
  }

  // Every other /keys path belongs to somebody else — the webhook doors under
  // /keys/me/webhooks are the alert module's — or to nobody, and the Worker's
  // own not_found is the right answer for the second.
  return null;
}

/**
 * Route one request to the key doors, or answer null when the path is not ours.
 * Storage failures become the same JSON 503 every other route gives.
 */
export async function handleKeys(
  request: Request,
  env: Env,
  deps: KeysDeps,
): Promise<Response | null> {
  const db = guardDatabase(env.DB);
  try {
    return await route(request, db, deps);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data, no secret.
      console.error(`keys: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}

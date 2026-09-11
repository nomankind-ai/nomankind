/**
 * The key doors: what a reader who wants more than the free tier knocks on.
 *
 * Whitepaper Section 9, Money: "The log is free to read at low volume, forever.
 * Revenue comes from high-rate API access, structured feeds and webhooks,
 * change alerts." Six doors and nothing else — what the tiers are, start a
 * checkout, claim the key the checkout paid for, what my key is, what my key
 * read, and the receipts behind that. A seventh, the customer's own billing
 * portal, is the provider's page and not ours: we hand out the link and hold
 * no card, no address and no invoice.
 *
 * The secret is shown exactly once, at the claim. There is no door that shows
 * it again, and there is no row anywhere that could: the table holds its hash
 * (src/keys.ts). A reader who loses a key cancels the subscription and buys
 * another, which is the honest consequence of not storing credentials.
 *
 * The claim answers HTML to a browser and JSON to everything else, because the
 * provider's success redirect lands a person on it and a person owed a
 * credential should not be shown a JSON blob they may close. The JSON is the
 * contract; the page is a courtesy, rendered through the same layout every other
 * page uses so it cannot drift into a second design.
 *
 * Nothing is decided here. What a tier costs and what it allows is
 * src/policy.ts's, what a key is and how one is minted is src/keys.ts's, the
 * provider is an injected adapter, and the store is query-shaped
 * (src/storage/keys.ts). No wall clock: `deps.now` is the instant the router
 * read once. No policy number lives here — the bare integers are HTTP status
 * codes, and the usage window's default and cap are the two named constants
 * below, which are page sizes of this door and not published amounts.
 */

import type { PaymentsAdapter } from "../adapters/stripe.js";
import {
  keyHash,
  keyStatusFromSubscription,
  looksLikeKey,
  mintKey,
  quotaScopeForKey,
  tierLimit,
  type KeyRecord,
} from "../keys.js";
import {
  CONTRIBUTOR_SHARE_FLOOR_PERCENT,
  CONTRIBUTOR_SHARE_PERCENT,
  FREE_TIER,
  LIST_PAGE_LIMIT,
  RATE_TIERS,
  READ_PRICE_MICROS_PER_READ,
  USAGE_DAYS_DEFAULT,
  USAGE_DAYS_MAX,
  isPaidTier,
} from "../policy.js";
import { html, htmlResponse, layout } from "../ui/html.js";
import type { PageContext } from "../ui/types.js";
import { utcDay } from "../anchor.js";
import type { D1Like } from "../storage/d1.js";
import {
  KeyClaimConflictError,
  keyByCheckoutSession,
  keyByHash,
  putKey,
  quotaDays,
  quotaOn,
  readCountEventOn,
  receiptsForKey,
} from "../storage/keys.js";
import type { Env } from "./env.js";
import { wantsHtml } from "./pages.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";

/** What the deps this door takes: the instant, and the payment provider. */
export interface KeysDeps {
  readonly now: Date;
  readonly payments: PaymentsAdapter;
}

/** How many milliseconds a day is. Not a policy number: it is what a day is. */
const MILLISECONDS_PER_DAY = 86_400_000;

/**
 * What an adapter refusal answers with.
 *
 * `payments_unavailable` is 503 and not 502: the paid loop is not configured on
 * this deployment, which is our state rather than the provider's failure, and it
 * is exactly production's state until M25. Everything else is 502 with the
 * detail the adapter chose, which is a status and an error code and never a
 * message, a request header or a secret.
 */
function fromAdapter(result: { refusal: string; detail?: string }): Response {
  if (result.refusal === "payments_unavailable") {
    return refuse(503, "payments_unavailable");
  }
  return json(
    {
      error: result.refusal,
      ...(result.detail === undefined ? {} : { detail: result.detail }),
    },
    502,
  );
}

/**
 * The key a request presented, or the refusal it earned.
 *
 * The identity checks only, and deliberately not the quota: these are a
 * holder's own account doors, not reading doors. A key at its daily cap must
 * still be able to see that it is at its cap, and a key whose bill did not
 * clear must still be able to reach the billing portal — a door that refused
 * `key_past_due` here would lock a customer out of the one page that fixes it.
 * The read and sync doors are where a status and a cap decide anything, through
 * `resolveAccess`.
 */
async function keyOf(
  db: D1Like,
  request: Request,
): Promise<{ ok: true; key: KeyRecord } | { ok: false; response: Response }> {
  const header = request.headers.get("authorization");
  if (header === null) {
    return { ok: false, response: refuse(401, "missing_key") };
  }
  const PREFIX = "bearer ";
  const presented = header.toLowerCase().startsWith(PREFIX)
    ? header.slice(PREFIX.length).trim()
    : header.trim();
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

/** What a tier costs and what it allows, straight out of policy. */
function tiers(): Response {
  return json(
    {
      tiers: RATE_TIERS,
      price_micros_per_read: READ_PRICE_MICROS_PER_READ,
      contributor_share_percent: CONTRIBUTOR_SHARE_PERCENT,
      contributor_share_floor_percent: CONTRIBUTOR_SHARE_FLOOR_PERCENT,
    },
    200,
  );
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
// Buying, claiming, and the provider's own page
// ---------------------------------------------------------------------------

/** Start a checkout for one tier. */
async function checkout(
  request: Request,
  env: Env,
  deps: KeysDeps,
  url: URL,
): Promise<Response> {
  let body: unknown;
  try {
    body = JSON.parse(await request.text());
  } catch {
    return refuse(400, "bad_body");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return refuse(400, "bad_body");
  }

  const fields = body as Record<string, unknown>;
  const tier = fields["tier"];
  const email = fields["email"];
  if (typeof tier !== "string") return refuse(400, "bad_body");
  if (email !== undefined && typeof email !== "string") {
    return refuse(400, "bad_body");
  }
  if (tier === FREE_TIER) return refuse(422, "free_tier_needs_no_key");
  if (!isPaidTier(tier)) return refuse(422, "unknown_tier");

  const price = await deps.payments.ensurePrice(env.ENVIRONMENT, tier);
  if (!price.ok) return fromAdapter(price);

  const session = await deps.payments.createCheckout({
    price: price.value.price,
    tier,
    environment: env.ENVIRONMENT,
    successUrl: `${url.origin}/keys/claim?session={CHECKOUT_SESSION_ID}`,
    cancelUrl: `${url.origin}/api`,
    ...(email === undefined ? {} : { email }),
  });
  if (!session.ok) return fromAdapter(session);

  return json({ session: session.value.id, url: session.value.url }, 200);
}

/**
 * Claim the key a finished checkout paid for.
 *
 * Every check before the write, and the write is the only place the secret
 * exists: it is minted, hashed, stored as the hash and handed back once. The
 * 409 is the unique index on `checkout_session` and not a check that hoped
 * nobody raced — two tabs open on the success URL both see nothing and both
 * insert, and exactly one of them gets a key.
 */
async function claim(
  request: Request,
  env: Env,
  deps: KeysDeps,
  db: D1Like,
  url: URL,
): Promise<Response> {
  const session = url.searchParams.get("session");
  if (session === null || session === "") {
    return answerClaim(request, env, url, refuse(400, "missing_session"), null);
  }

  const retrieved = await deps.payments.retrieveCheckout(session);
  if (!retrieved.ok) {
    return answerClaim(request, env, url, fromAdapter(retrieved), null);
  }
  const checkoutSession = retrieved.value;

  if (checkoutSession.status === "expired") {
    return answerClaim(request, env, url, refuse(404, "unknown_session"), null);
  }
  if (
    checkoutSession.status !== "complete" ||
    checkoutSession.subscription === null ||
    checkoutSession.customer === null
  ) {
    return answerClaim(request, env, url, refuse(402, "not_paid"), null);
  }

  const tier = checkoutSession.metadata["tier"];
  if (tier === undefined || !isPaidTier(tier)) {
    return answerClaim(request, env, url, refuse(422, "unknown_tier"), null);
  }

  const standing = await keyByCheckoutSession(db, session);
  if (standing !== null) {
    return answerClaim(request, env, url, refuse(409, "already_claimed"), null);
  }

  const minted = mintKey();
  const at = deps.now.toISOString();
  let stored: KeyRecord;
  try {
    stored = await putKey(db, {
      id: minted.id,
      keyHash: await minted.hash,
      tier,
      status: keyStatusFromSubscription(checkoutSession.subscription.status),
      customer: checkoutSession.customer,
      subscription: checkoutSession.subscription.id,
      checkoutSession: session,
      createdAt: at,
    });
  } catch (error) {
    if (error instanceof KeyClaimConflictError) {
      return answerClaim(request, env, url, refuse(409, "already_claimed"), null);
    }
    throw error;
  }

  const body = {
    key: minted.secret,
    id: stored.id,
    tier: stored.tier,
    status: stored.status,
    customer: stored.customer,
    created_at: stored.created_at,
  };
  return answerClaim(request, env, url, json(body, 201), body);
}

/**
 * The claim's answer in the shape the caller asked for.
 *
 * The JSON is the contract and is what an agent gets. A browser — which is what
 * the provider's success redirect sends here — gets the same fields on a page,
 * through the layout every other page uses, with the one warning that matters:
 * the key is on this page and nowhere else, ever again.
 */
function answerClaim(
  request: Request,
  env: Env,
  url: URL,
  response: Response,
  granted: {
    key: string;
    id: string;
    tier: string;
    status: string;
    customer: string;
    created_at: string;
  } | null,
): Response {
  if (request.method !== "GET" || !wantsHtml(request)) return response;

  const ctx: PageContext = {
    environment: env.ENVIRONMENT,
    path: url.pathname,
    origin: url.origin,
  };

  if (granted === null) {
    const heading = response.status === 409 ? "Already claimed" : "No key";
    return htmlResponse(
      layout(ctx, {
        title: heading,
        body: html`<section class="panel">
          <h1>${heading}</h1>
          <p>
            This checkout session did not hand over a key. The JSON at this same
            address says why, in one word.
          </p>
        </section>`,
      }),
      response.status,
    );
  }

  const rows = [
    ["Key", granted.key],
    ["Id", granted.id],
    ["Tier", granted.tier],
    ["Status", granted.status],
    ["Customer", granted.customer],
    ["Created", granted.created_at],
  ].map(
    ([name, value]) =>
      html`<tr>
        <th>${name}</th>
        <td class="mono">${value}</td>
      </tr>`,
  );

  return htmlResponse(
    layout(ctx, {
      title: "Your key",
      body: html`<section class="panel">
        <h1>Your key</h1>
        <p>
          <strong>This is the only time the key is shown.</strong> It is stored
          here as a hash and cannot be shown again. Copy it now; if you lose it,
          cancel the subscription and buy another.
        </p>
        <table class="table">
          ${rows}
        </table>
        <p>Send it as <code>Authorization: Bearer &lt;key&gt;</code>.</p>
      </section>`,
    }),
    201,
  );
}

/** The provider's own billing page, for the customer behind one key. */
async function portal(
  key: KeyRecord,
  deps: KeysDeps,
  url: URL,
): Promise<Response> {
  const session = await deps.payments.createPortal(
    key.customer,
    `${url.origin}/api`,
  );
  if (!session.ok) return fromAdapter(session);
  return json({ url: session.value.url }, 200);
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

async function route(
  request: Request,
  env: Env,
  db: D1Like,
  deps: KeysDeps,
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/keys/tiers") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return tiers();
  }

  if (path === "/keys/checkout") {
    if (request.method !== "POST") return methodNotAllowed("POST");
    return checkout(request, env, deps, url);
  }

  if (path === "/keys/claim") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return claim(request, env, deps, db, url);
  }

  if (path === "/keys/me") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    const held = await keyOf(db, request);
    return held.ok ? me(db, held.key, deps.now) : held.response;
  }

  if (path === "/keys/me/usage") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    const held = await keyOf(db, request);
    return held.ok ? usage(db, held.key, url, deps.now) : held.response;
  }

  if (path === "/keys/me/receipts") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    const held = await keyOf(db, request);
    return held.ok ? receipts(db, held.key, url) : held.response;
  }

  if (path === "/keys/me/portal") {
    if (request.method !== "POST") return methodNotAllowed("POST");
    const held = await keyOf(db, request);
    return held.ok ? portal(held.key, deps, url) : held.response;
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
    return await route(request, env, db, deps);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data, no secret.
      console.error(`keys: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}

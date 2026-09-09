/**
 * The frozen reader's door.
 *
 * Whitepaper Section 8, "The frozen reader": "The request names a subject and a
 * category, or an entry id, and optionally a minimum tier and a maximum age. The
 * response is the entry record as in Section 3, the inclusion proof for its
 * seal, and a signed read receipt naming the entry, the time, and a running
 * counter."
 *
 * Two routes and one answer shape. `GET /read/{id}` names an entry;
 * `GET /read?subject=&category=` asks nomankind to choose the current answer,
 * with `min_tier` and `max_age` as the reader's two demands. Both return
 * `{entry, sidecar, seal, receipt}`: the entry exactly as it is stored, the
 * sidecar beside it, the seal covering the entry's submission — the entry's own
 * `seal` object already carries the inclusion proof, its position and the
 * witnesses, so the seal record here is what a reader checks that proof against —
 * and the signed receipt.
 *
 * Nothing is decided here. Which queries are legal and which entry answers one
 * are src/read.ts's pure functions, the candidate list comes newest-submission
 * first from the store, and the receipt is built and signed by src/receipt.ts.
 * This file only gathers the facts, in order, and refuses in the kernel's own
 * words.
 *
 * The receipt is persisted before the response is sent, so a receipt in a
 * reader's hands always has a row behind it: a counter a reader holds and the
 * log cannot account for would be exactly the hole Section 9 asks readers to
 * look for. The counter is the database's to hand out — two isolates asking at
 * the same instant read the same number and the unique index refuses the second
 * — so a conflict is answered by signing again for the next number, at most
 * three attempts, and then 503 rather than a receipt whose number is a guess.
 *
 * An entry that is not verified never issues a receipt and never moves the
 * counter: it was not served, so nobody read it.
 *
 * No wall clock: `deps.now` is the instant the router read once for the whole
 * request. No policy number lives here — the bare integers are HTTP status codes
 * and the page size is LIST_PAGE_LIMIT from src/policy.ts.
 */

import { extractCore } from "../core.js";
import { base64urlDecode } from "../encoding.js";
import { entryHash } from "../hash.js";
import { agentIdFromPublicKey, importPrivateKeyPkcs8 } from "../identity.js";
import { LIST_PAGE_LIMIT } from "../policy.js";
import { chooseReadable, parseReadQuery, type ReadQuery } from "../read.js";
import { signReadReceipt, type ReadReceipt } from "../receipt.js";
import type { Entry } from "../schema.js";
import type { D1Like } from "../storage/d1.js";
import {
  ReceiptConflictError,
  getEntry,
  nextReadCounter,
  putReadReceipt,
  readCandidates,
  sealCovering,
  type StoredEntry,
} from "../storage/repository.js";
import type { Env } from "./env.js";
import {
  StorageUnreachable,
  guardDatabase,
  json,
  methodNotAllowed,
  refuse,
} from "./registry.js";

/** The ids nomankind mints, exactly as src/read.ts narrows the schema's pattern. */
const ENTRY_ID_PATTERN = /^nmk_[0-9a-f]{32}$/;

/**
 * How many times a reader's receipt may be signed again for a counter another
 * isolate took first. A retry budget, not a policy number: it bounds a loop
 * whose every iteration is a real conflict, and the answer when it runs out is a
 * refusal rather than an unnumbered receipt.
 */
const RECEIPT_ATTEMPTS = 3;

/**
 * The key that signs receipts, and the agent id it belongs to.
 *
 * Exported because the delta stream signs its own receipts with exactly this
 * key (src/worker/sync.ts): one sealing agent signs everything nomankind hands
 * out, and two routes importing two copies of the import would be two chances
 * to disagree about who that agent is.
 */
export interface ReceiptSigner {
  readonly key: CryptoKey;
  readonly issuer: string;
}

/**
 * One import per key string, kept for the life of the isolate.
 *
 * Importing a PKCS#8 key and exporting its public half to name the issuer is
 * work that never changes for a given secret, and a read is the one route that
 * would pay for it on every request. Keyed by the string rather than by the env
 * object, because an env is rebuilt per request and the secret is not.
 *
 * A key that cannot be read memoizes as null, which is the same answer as no key
 * at all: the route refuses rather than issuing an unsigned receipt.
 */
const SIGNERS = new Map<string, Promise<ReceiptSigner | null>>();

/**
 * Read the sealing agent's private key, exactly as `sealingAgentIdFor` reads it
 * (src/adapters/witness.ts): unpadded base64url PKCS#8, and the agent id from
 * the public half the OKP JWK carries in `x`, so the two can never disagree
 * about who nomankind's agent is.
 *
 * Null on anything unreadable, and never a throw: an unconfigured key is a route
 * that refuses, not a Worker that stops.
 */
async function importSigner(secret: string): Promise<ReceiptSigner | null> {
  try {
    const key = await importPrivateKeyPkcs8(base64urlDecode(secret));
    const jwk = (await globalThis.crypto.subtle.exportKey(
      "jwk",
      key,
    )) as JsonWebKey;
    const x = jwk.x;
    if (typeof x !== "string") return null;
    return { key, issuer: agentIdFromPublicKey(base64urlDecode(x)) };
  } catch {
    // The secret never reaches a message: an error carrying it would publish it.
    return null;
  }
}

/**
 * The memoized signer for this environment's secret, or null when there is
 * none. Shared with the sync route, so the import is paid for once per isolate
 * however many doors ask for it.
 */
export function signerFor(
  secret: string | undefined,
): Promise<ReceiptSigner | null> {
  if (secret === undefined || secret === "") return Promise.resolve(null);
  const memoized = SIGNERS.get(secret);
  if (memoized !== undefined) return memoized;
  const pending = importSigner(secret);
  SIGNERS.set(secret, pending);
  return pending;
}

/** A required string field on a stored entry, read by the schema's own name. */
function field(entry: Entry, name: string): string {
  return (entry as unknown as Record<string, unknown>)[name] as string;
}

/** A nullable string field on a stored entry. */
function nullableField(entry: Entry, name: string): string | null {
  const value = (entry as unknown as Record<string, unknown>)[name];
  return typeof value === "string" ? value : null;
}

/**
 * Sign and store one receipt, or null when every attempt lost the counter.
 *
 * The counter is inside the signed bytes, so a conflict cannot be repaired by
 * editing the row: the receipt is signed again, from a freshly read counter.
 * `created_at` is the receipt's own `read_at`, so the day a receipt belongs to
 * and the day it is counted on are the same day by construction.
 */
async function issueReceipt(
  db: D1Like,
  entry: Entry,
  signer: ReceiptSigner,
  now: Date,
): Promise<ReadReceipt | null> {
  const entryId = field(entry, "id");
  const hash = await entryHash(extractCore(entry));
  const readAt = now.toISOString();

  for (let attempt = 0; attempt < RECEIPT_ATTEMPTS; attempt += 1) {
    const counter = await nextReadCounter(db);
    const receipt = await signReadReceipt(
      {
        entry_id: entryId,
        entry_hash: hash,
        read_at: readAt,
        counter,
        issuer: signer.issuer,
      },
      signer.key,
    );
    try {
      await putReadReceipt(db, { entryId, createdAt: readAt, receipt });
      return receipt;
    } catch (error) {
      if (error instanceof ReceiptConflictError) continue;
      throw error;
    }
  }
  return null;
}

/**
 * Serve one entry: the receipt first, then the answer.
 *
 * The receipt is persisted before the response is built, so there is no path on
 * which a reader holds a receipt the table does not. The seal is read after, and
 * is null while nothing has sealed the entry's submission yet.
 */
async function serve(
  db: D1Like,
  stored: StoredEntry,
  env: Env,
  now: Date,
): Promise<Response> {
  const signer = await signerFor(env.SEALING_AGENT_KEY);
  if (signer === null) return refuse(503, "receipts_not_configured");

  const receipt = await issueReceipt(db, stored.entry, signer, now);
  if (receipt === null) return refuse(503, "receipt_conflict");

  const seal = await sealCovering(db, stored.submittedSeq);
  return json(
    {
      entry: stored.entry,
      sidecar: stored.sidecar,
      seal,
      receipt,
    },
    200,
  );
}

/**
 * One entry by id.
 *
 * An entry that is not verified is 409 rather than 404: it exists, and telling
 * the reader its status and what superseded it is the honest answer. No receipt
 * is issued and the counter does not move, because nothing was served.
 */
async function byId(
  db: D1Like,
  id: string,
  env: Env,
  now: Date,
): Promise<Response> {
  if (!ENTRY_ID_PATTERN.test(id)) return refuse(400, "bad_id");

  const stored = await getEntry(db, id);
  if (stored === null) return refuse(404, "not_found");

  const status = field(stored.entry, "status");
  if (status !== "verified") {
    return json(
      {
        error: "entry_not_verified",
        status,
        superseded_by: nullableField(stored.entry, "superseded_by"),
      },
      409,
    );
  }

  return serve(db, stored, env, now);
}

/**
 * The current answer about one subject in one category.
 *
 * The store offers verified entries newest submission first, a page at a time,
 * and `chooseReadable` takes the first that clears the reader's tier and age
 * demands. Paging continues until something is chosen or the candidates run out,
 * so a reader demanding observed evidence is not refused merely because the
 * newest page happened to hold none.
 */
async function bySubject(
  db: D1Like,
  query: Extract<ReadQuery, { by: "subject" }>,
  env: Env,
  now: Date,
): Promise<Response> {
  let beforeSubmittedSeq: number | undefined;
  for (;;) {
    const page = await readCandidates(db, {
      subject: query.subject,
      category: query.category,
      limit: LIST_PAGE_LIMIT,
      ...(beforeSubmittedSeq === undefined ? {} : { beforeSubmittedSeq }),
    });
    if (page.length === 0) break;

    const chosen = chooseReadable(
      page.map((row) => ({ entry: row.entry, sidecar: row.sidecar })),
      query,
      now,
    );
    if (chosen !== null) {
      const id = field(chosen.entry, "id");
      const stored = page.find((row) => field(row.entry, "id") === id);
      if (stored !== undefined) return serve(db, stored, env, now);
    }

    if (page.length < LIST_PAGE_LIMIT) break;
    beforeSubmittedSeq = page[page.length - 1]!.submittedSeq;
  }

  return refuse(404, "no_entry");
}

/** The one path segment after `/read/`, or null when the path is not that shape. */
function idAfterPrefix(path: string): string | null {
  const PREFIX = "/read/";
  if (!path.startsWith(PREFIX)) return null;
  const rest = path.slice(PREFIX.length);
  if (rest === "" || rest.includes("/")) return null;
  try {
    return decodeURIComponent(rest);
  } catch {
    return null;
  }
}

async function route(
  request: Request,
  env: Env,
  db: D1Like,
  now: Date,
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  const id = idAfterPrefix(path);
  if (id !== null) {
    if (request.method !== "GET") return methodNotAllowed("GET");
    return byId(db, id, env, now);
  }

  if (path === "/read") {
    if (request.method !== "GET") return methodNotAllowed("GET");
    const parsed = parseReadQuery(url.searchParams);
    // The refusal goes out in the kernel's own word, so a reader who mistyped
    // `min_tier` is told which rule refused them rather than "bad request".
    if (!parsed.ok) return refuse(400, parsed.reason);
    return parsed.query.by === "entry"
      ? byId(db, parsed.query.entry_id, env, now)
      : bySubject(db, parsed.query, env, now);
  }

  return null;
}

/**
 * Route one request to the read door, or answer null when the path is not ours,
 * which leaves the Worker's own not_found untouched. Storage failures become the
 * same JSON 503 every other route gives.
 */
export async function handleRead(
  request: Request,
  env: Env,
  deps: { now: Date },
): Promise<Response | null> {
  const db = guardDatabase(env.DB);
  try {
    return await route(request, env, db, deps.now);
  } catch (error) {
    if (error instanceof StorageUnreachable) {
      // The message only: no binding contents, no request data, no secret.
      console.error(`read: storage unreachable: ${error.message}`);
      return refuse(503, "storage_unreachable");
    }
    throw error;
  }
}

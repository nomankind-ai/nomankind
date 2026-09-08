/**
 * The spent-nonce store, in D1.
 *
 * Decision D-014: a signed write request carries a single-use nonce, and the
 * verifier refuses a request whose nonce it has already seen. The in-memory
 * store in src/request.ts is a single process's memory, which a Worker does not
 * have: two requests may land in two isolates, so the memory that matters has
 * to be the database.
 *
 * Nothing here reads a clock. `add` takes the expiry the caller computed from
 * the injected clock and the retention window, and `prune` takes the instant to
 * prune at, so the same rules that make the kernel testable hold here too.
 */

import type { NonceStore } from "../request.js";
import type { D1Like } from "./d1.js";

/**
 * `LIMIT 1` says "the one row this lookup can return", which is a fact about
 * the query rather than a page size. No policy number appears in this module.
 */
const ONE_ROW = "LIMIT 1";

/** A NonceStore backed by the `nonces` table (migrations/0002_registry.sql). */
export class D1NonceStore implements NonceStore {
  readonly #db: D1Like;

  constructor(db: D1Like) {
    this.#db = db;
  }

  /** Whether this nonce has already been spent. */
  async has(nonce: string): Promise<boolean> {
    const row = await this.#db
      .prepare(`SELECT nonce FROM nonces WHERE nonce = ? ${ONE_ROW}`)
      .bind(nonce)
      .first();
    return row !== null;
  }

  /**
   * Remember a spent nonce until `expiresAt`.
   *
   * INSERT OR REPLACE rather than a plain insert: a nonce already remembered is
   * already refused by `has`, and a second write of the same value must not
   * turn a correctly-refused replay into a database error.
   */
  async add(nonce: string, expiresAt: Date): Promise<void> {
    await this.#db
      .prepare(`INSERT OR REPLACE INTO nonces (nonce, expires_at) VALUES (?, ?)`)
      .bind(nonce, expiresAt.toISOString())
      .run();
  }

  /**
   * Drop every nonce whose retention has run out at `now`. Strictly before, so
   * a nonce is remembered through the whole of its last instant.
   */
  async prune(now: Date): Promise<void> {
    await this.#db
      .prepare(`DELETE FROM nonces WHERE expires_at < ?`)
      .bind(now.toISOString())
      .run();
  }
}

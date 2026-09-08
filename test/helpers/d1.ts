/**
 * A real D1 database for the storage tests.
 *
 * miniflare's D1, through wrangler's `getPlatformProxy`, is the same SQLite
 * engine Cloudflare runs, so these tests exercise the actual query planner and
 * the actual JSON round-trip rather than a hand-written fake. `persist: false`
 * keeps the database in memory and gives a fresh one per call — verified: a
 * second proxy opened after the first is disposed cannot see the first one's
 * tables — so no test can leak into another.
 *
 * The `node:fs` loading lives here rather than in src/storage, because src/ has
 * to run unchanged on Workers and a `node:` import there would be a lie about
 * where the code can run.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { getPlatformProxy } from "wrangler";
import type { D1Like } from "../../src/storage/d1.js";
import type { R2Like } from "../../src/storage/r2.js";
import {
  applyMigrations,
  migrationsInOrder,
  type Migration,
} from "../../src/storage/migrate.js";

/** The repository root, resolved from this file so the cwd does not matter. */
const ROOT = fileURLToPath(new URL("../../", import.meta.url));

export const CONFIG_PATH = join(ROOT, "wrangler.jsonc");
export const MIGRATIONS_DIR = join(ROOT, "migrations");

/** The migration files, in the order `applyMigrations` will run them. */
export function loadMigrations(directory: string = MIGRATIONS_DIR): Migration[] {
  const files = readdirSync(directory).map((name) => ({
    name,
    sql: readFileSync(join(directory, name), "utf8"),
  }));
  return migrationsInOrder(files);
}

/** The bindings a test opens, and the handle that shuts the process down. */
export interface TestDatabase {
  readonly db: D1Like;
  /**
   * The snapshot archive. `getPlatformProxy` hands back every binding
   * wrangler.jsonc declares, so this is miniflare's own R2 behind the same
   * `persist: false` as the database: fresh per call, in memory, and gone with
   * `dispose`.
   */
  readonly captures: R2Like;
  readonly dispose: () => Promise<void>;
}

/**
 * Open a fresh, migrated database.
 *
 * The caller must call `dispose` — `getPlatformProxy` starts a child process,
 * and vitest will hold the run open until it is stopped.
 */
export async function openTestDatabase(): Promise<TestDatabase> {
  const platform = await getPlatformProxy<{ DB: D1Like; CAPTURES: R2Like }>({
    configPath: CONFIG_PATH,
    persist: false,
  });
  await applyMigrations(platform.env.DB, loadMigrations());
  return {
    db: platform.env.DB,
    captures: platform.env.CAPTURES,
    dispose: () => platform.dispose(),
  };
}

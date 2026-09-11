/**
 * The two migration runners have to agree.
 *
 * Decision D-022: migrations are numbered, forward-only, and applied by the
 * deploy workflow with `wrangler d1 migrations apply` before the Worker goes
 * live. But the Worker and the tests apply them through `applyMigrations`. If
 * the two disagreed about which migrations have already run — a different
 * tracking table, different columns, a different recorded name — a deploy would
 * replay 0001 over a live database.
 *
 * So this test runs the real CLI against a real local database, twice, and then
 * compares the tracking table it created against the one `applyMigrations`
 * creates. It is slower than the rest of the suite on purpose: the thing being
 * checked is the CLI's actual behaviour, not a description of it.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getPlatformProxy } from "wrangler";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { D1Like } from "../src/storage/d1.js";
import { MIGRATIONS_TABLE } from "../src/storage/migrate.js";
import { CONFIG_PATH, openTestDatabase, type TestDatabase } from "./helpers/d1.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const WRANGLER = join(ROOT, "node_modules", "wrangler", "bin", "wrangler.js");

/**
 * miniflare lays its state out as `<persist-to>/v3/<binding kind>`, and
 * `getPlatformProxy`'s `persist.path` names the `v3` directory itself. Reading
 * back what the CLI wrote means pointing at that one, not at the root.
 */
const MINIFLARE_STATE = "v3";

/** The CLI, run from the repository root with the toolchain on PATH. */
function wrangler(args: string[]): { status: number; output: string } {
  const toolPath = [
    join(ROOT, ".tools", "node", "bin"),
    join(ROOT, ".tools", "gh", "bin"),
    process.env["PATH"] ?? "",
  ].join(delimiter);

  const result = spawnSync(process.execPath, [WRANGLER, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: toolPath,
      // Nothing here should reach Cloudflare; --local is the whole point.
      WRANGLER_SEND_METRICS: "false",
      CI: "true",
    },
  });
  return {
    status: result.status ?? -1,
    output: `${result.stdout ?? ""}${result.stderr ?? ""}`,
  };
}

/** The tracking table's shape, as SQLite itself reports it. */
async function trackingTable(db: D1Like): Promise<{
  sql: string | null;
  columns: unknown[];
}> {
  const created = await db
    .prepare(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`)
    .bind(MIGRATIONS_TABLE)
    .first<{ sql: string }>();
  const columns = await db
    .prepare(`PRAGMA table_info("${MIGRATIONS_TABLE}")`)
    .all<Record<string, unknown>>();
  return { sql: created === null ? null : created.sql, columns: columns.results };
}

describe("wrangler d1 migrations apply", () => {
  let persistTo: string;
  let byCli: { sql: string | null; columns: unknown[] };
  let first: { status: number; output: string };
  let second: { status: number; output: string };
  let ours: TestDatabase;

  beforeAll(async () => {
    persistTo = mkdtempSync(join(tmpdir(), "nmk-d1-"));
    const args = [
      "d1",
      "migrations",
      "apply",
      "nomankind-local",
      "--local",
      "--config",
      CONFIG_PATH,
      "--persist-to",
      persistTo,
    ];
    first = wrangler(args);
    second = wrangler(args);

    const platform = await getPlatformProxy<{ DB: D1Like }>({
      configPath: CONFIG_PATH,
      persist: { path: join(persistTo, MINIFLARE_STATE) },
    });
    try {
      byCli = await trackingTable(platform.env.DB);
    } finally {
      await platform.dispose();
    }

    ours = await openTestDatabase();
  }, 180_000);

  afterAll(async () => {
    await ours?.dispose();
    if (persistTo !== undefined) rmSync(persistTo, { recursive: true, force: true });
  });

  it("applies the numbered migrations", () => {
    expect(first.status).toBe(0);
    expect(first.output).toContain("0001_init.sql");
  });

  it("applies nothing the second time", () => {
    expect(second.status).toBe(0);
    expect(second.output).toContain("No migrations to apply");
  });

  it("creates the same tracking table applyMigrations does", async () => {
    const byUs = await trackingTable(ours.db);
    expect(byCli.sql).not.toBeNull();
    expect(byUs.sql).toBe(byCli.sql);
    expect(byUs.columns).toEqual(byCli.columns);
  });

  it("records the migration under the same name applyMigrations does", async () => {
    const platform = await getPlatformProxy<{ DB: D1Like }>({
      configPath: CONFIG_PATH,
      persist: { path: join(persistTo, MINIFLARE_STATE) },
    });
    try {
      const applied = await platform.env.DB.prepare(
        `SELECT name FROM "${MIGRATIONS_TABLE}" ORDER BY id`,
      ).all<{ name: string }>();
      const oursApplied = await ours.db
        .prepare(`SELECT name FROM "${MIGRATIONS_TABLE}" ORDER BY id`)
        .all<{ name: string }>();
      expect(applied.results.map((row) => row.name)).toEqual([
        "0001_init.sql",
        "0002_registry.sql",
        "0003_captures.sql",
        "0004_assignments.sql",
        "0005_freshness.sql",
        "0006_sealing.sql",
        "0007_receipts.sql",
        "0008_sync.sql",
        "0009_disputes.sql",
        "0010_ledger.sql",
        "0011_attestations.sql",
        "0012_domains.sql",
        "0013_status.sql",
        "0014_mirror.sql",
        "0015_paid_access.sql",
      ]);
      expect(oursApplied.results.map((row) => row.name)).toEqual(
        applied.results.map((row) => row.name),
      );
    } finally {
      await platform.dispose();
    }
  }, 60_000);
});

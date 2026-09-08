/**
 * Forward-only, numbered migrations.
 *
 * Decision D-022, and the PoC retrospective's DEPLOY-1: migrations are numbered,
 * applied in name order, never edited after merge, and applied by the deploy
 * workflow before the Worker goes live. This module is the runtime half of that:
 * the same rule, applied from inside a Worker or a test, against the same
 * tracking table `wrangler d1 migrations apply` uses.
 *
 * The tracking table matters more than it looks. A database migrated by wrangler
 * and one migrated by this function must agree about what has already run, or a
 * deploy would replay 0001 over a live database. So the table name, its columns,
 * and the name recorded for each migration are copied from wrangler's own
 * behaviour: table `d1_migrations`, columns `id` / `name` / `applied_at`, and the
 * name is the migration's file name including the `.sql` suffix.
 *
 * Nothing here reads the filesystem. Loading `migrations/*.sql` is the caller's
 * job (test/helpers/d1.ts does it with node:fs) because src/ must stay free of
 * `node:` imports to run unchanged on Workers.
 */

import type { D1Like, D1LikeStatement } from "./d1.js";

/** One migration: the file name, and the SQL it holds. */
export interface Migration {
  readonly name: string;
  readonly sql: string;
}

/** The tracking table's name, as `wrangler d1 migrations apply` creates it. */
export const MIGRATIONS_TABLE = "d1_migrations";

/**
 * The tracking table, character for character as wrangler creates it. IF NOT
 * EXISTS is wrangler's, not ours: this one table is created by both runners, so
 * whichever gets there first wins and the other must not fail.
 */
export const CREATE_MIGRATIONS_TABLE =
  `CREATE TABLE IF NOT EXISTS "${MIGRATIONS_TABLE}"(\n` +
  "\t\tid         INTEGER PRIMARY KEY AUTOINCREMENT,\n" +
  "\t\tname       TEXT UNIQUE,\n" +
  "\t\tapplied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL\n" +
  ");";

/** The file suffix a migration must carry to be one. */
const MIGRATION_SUFFIX = ".sql";

/**
 * The migrations that will run, in the order they will run in.
 *
 * Pure: it takes what the caller loaded and returns a sorted copy. Names sort
 * bytewise, which is what makes the numeric prefix load-bearing — `0002_` after
 * `0001_`, and a name without a prefix is a mistake the ordering will expose
 * rather than hide.
 */
export function migrationsInOrder(
  migrations: readonly Migration[],
): Migration[] {
  return [...migrations]
    .filter((migration) => migration.name.endsWith(MIGRATION_SUFFIX))
    .sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    );
}

/**
 * Split a migration file into the statements D1 will run.
 *
 * D1 has no multi-statement `prepare`, so a file has to be split before it can
 * go into a batch. The split respects single-quoted strings, double-quoted
 * identifiers, line comments and block comments, so a semicolon inside any of
 * those is not a statement boundary. A fragment holding nothing
 * but comments and whitespace is dropped.
 */
export function splitStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = "";
  let hasCode = false;
  let index = 0;

  const flush = (): void => {
    if (hasCode) statements.push(current.trim());
    current = "";
    hasCode = false;
  };

  while (index < sql.length) {
    const char = sql[index]!;
    const next = sql[index + 1];

    if (char === "-" && next === "-") {
      const end = sql.indexOf("\n", index);
      const stop = end === -1 ? sql.length : end;
      current += sql.slice(index, stop);
      index = stop;
      continue;
    }
    if (char === "/" && next === "*") {
      const end = sql.indexOf("*/", index + 2);
      const stop = end === -1 ? sql.length : end + 2;
      current += sql.slice(index, stop);
      index = stop;
      continue;
    }
    if (char === "'" || char === '"') {
      const quote = char;
      let cursor = index + 1;
      while (cursor < sql.length) {
        if (sql[cursor] === quote) {
          if (sql[cursor + 1] === quote) {
            cursor += 2;
            continue;
          }
          cursor += 1;
          break;
        }
        cursor += 1;
      }
      current += sql.slice(index, cursor);
      hasCode = true;
      index = cursor;
      continue;
    }
    if (char === ";") {
      flush();
      index += 1;
      continue;
    }
    current += char;
    if (char.trim() !== "") hasCode = true;
    index += 1;
  }
  flush();
  return statements;
}

/** A migration that failed, named so a deploy log says which file broke. */
export class MigrationError extends Error {
  override readonly name = "MigrationError";
  readonly migration: string;

  constructor(migration: string, cause: unknown) {
    super(
      `migration ${migration} failed: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
    this.migration = migration;
    this.cause = cause;
  }
}

/** The migration names already recorded in the tracking table. */
async function appliedNames(db: D1Like): Promise<Set<string>> {
  const applied = await db
    .prepare(`SELECT name FROM "${MIGRATIONS_TABLE}" ORDER BY id`)
    .all<{ name: string | null }>();
  const names = new Set<string>();
  for (const row of applied.results) {
    if (typeof row.name === "string") names.add(row.name);
  }
  return names;
}

/**
 * Apply every migration not yet recorded, in name order, and return the names
 * applied.
 *
 * Each migration is one batch: its statements and the row that records it go in
 * together, so a migration is either applied and recorded or neither. A second
 * call finds every name already recorded and returns an empty array — the
 * idempotence lives here, in the tracking table, not in the SQL, which is why
 * the migration files carry no IF NOT EXISTS.
 *
 * Forward-only: nothing in this module removes a row from the tracking table or
 * runs a migration a second time. There is no down migration by design.
 */
export async function applyMigrations(
  db: D1Like,
  migrations: readonly Migration[],
): Promise<string[]> {
  await db.prepare(CREATE_MIGRATIONS_TABLE).run();
  const already = await appliedNames(db);
  const applied: string[] = [];

  for (const migration of migrationsInOrder(migrations)) {
    if (already.has(migration.name)) continue;
    const statements: D1LikeStatement[] = splitStatements(migration.sql).map(
      (statement) => db.prepare(statement),
    );
    statements.push(
      db
        .prepare(`INSERT INTO "${MIGRATIONS_TABLE}" (name) VALUES (?)`)
        .bind(migration.name),
    );
    try {
      await db.batch(statements);
    } catch (cause) {
      throw new MigrationError(migration.name, cause);
    }
    applied.push(migration.name);
  }
  return applied;
}

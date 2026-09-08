/**
 * The narrow D1 surface the storage layer uses.
 *
 * Whitepaper Section 11, Deployment and status: the Worker runs on Cloudflare,
 * so the database is D1. Nothing here imports a `node:` module and nothing here
 * imports generated Worker types: the interface is structural and small enough
 * that miniflare's `D1Database` (and the real one) satisfies it as it stands.
 * That keeps the kernel buildable with the approved dependency baseline and
 * keeps the tests free to hand in any object with these four methods.
 *
 * Only the members the repository actually calls are declared. `raw`, `dump`,
 * `withSession` and the rest of D1's API are deliberately absent: an interface
 * that names them would be a promise this layer does not need to keep.
 */

/** The `meta` block D1 attaches to a result. Opaque here: nothing reads it. */
export type D1LikeMeta = Record<string, unknown>;

/** A statement's result set. */
export interface D1LikeResult<Row = Record<string, unknown>> {
  readonly results: Row[];
  readonly success: boolean;
  readonly meta?: D1LikeMeta;
}

/** What `exec` reports. */
export interface D1LikeExecResult {
  readonly count: number;
  readonly duration: number;
}

/** A prepared statement, before or after its parameters are bound. */
export interface D1LikeStatement {
  bind(...values: unknown[]): D1LikeStatement;
  first<Row = Record<string, unknown>>(): Promise<Row | null>;
  all<Row = Record<string, unknown>>(): Promise<D1LikeResult<Row>>;
  run<Row = Record<string, unknown>>(): Promise<D1LikeResult<Row>>;
}

/** The database handle every repository function takes as its first argument. */
export interface D1Like {
  prepare(sql: string): D1LikeStatement;
  batch<Row = Record<string, unknown>>(
    statements: D1LikeStatement[],
  ): Promise<D1LikeResult<Row>[]>;
  exec(sql: string): Promise<D1LikeExecResult>;
}

/** One row as it comes back from D1: column name to value. */
export type Row = Record<string, unknown>;

/**
 * Read a text column that the schema declares NOT NULL. Throws rather than
 * coercing: a null here means the row was written by something that did not go
 * through this module, and guessing would hide that.
 */
export function readText(row: Row, column: string): string {
  const value = row[column];
  if (typeof value !== "string") {
    throw new TypeError(`column ${column}: expected TEXT, got ${typeof value}`);
  }
  return value;
}

/** Read a nullable text column. */
export function readNullableText(row: Row, column: string): string | null {
  const value = row[column];
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") {
    throw new TypeError(`column ${column}: expected TEXT or null`);
  }
  return value;
}

/** Read an INTEGER column the schema declares NOT NULL. */
export function readInteger(row: Row, column: string): number {
  const value = row[column];
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new TypeError(`column ${column}: expected INTEGER`);
  }
  return value;
}

/** Read a nullable INTEGER column. */
export function readNullableInteger(row: Row, column: string): number | null {
  const value = row[column];
  if (value === null || value === undefined) return null;
  return readInteger(row, column);
}

/** Read an INTEGER column holding 0 or 1 as the boolean it stands for. */
export function readBoolean(row: Row, column: string): boolean {
  return readInteger(row, column) !== 0;
}

/** Write a boolean into an INTEGER column. */
export function writeBoolean(value: boolean): number {
  return value ? 1 : 0;
}

/**
 * Read a JSON column back into the object that was stored.
 *
 * The repository stores `JSON.stringify` of a kernel object and parses it here,
 * so what comes out is deep-equal to what went in. Nothing is reshaped on the
 * way through: a derived field written by `deriveEntry` comes back exactly as
 * derivation left it.
 */
export function readJson<T>(row: Row, column: string): T {
  return JSON.parse(readText(row, column)) as T;
}

/** Write a kernel object into a JSON column. */
export function writeJson(value: unknown): string {
  return JSON.stringify(value);
}

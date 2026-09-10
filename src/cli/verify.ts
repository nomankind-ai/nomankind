/**
 * verify: the paper's one script.
 *
 * Whitepaper, Goals and non-goals, goal 4: "anyone can check the proof offline
 * with two files and one script". The two files are an entry and the log bundle
 * beside it; this is the script. It reads them, hands them to the pure kernel
 * (src/verify.ts) and prints what comes back — nothing here decides anything.
 *
 * The exit code is the whole answer: 0 when the entry checks out, 1 when it does
 * not or when a file cannot be read, 2 when the command was called wrong. A
 * stranger's file is data, never a crash: an unreadable or unparsable file gets
 * one named line on stderr and never a stack trace.
 *
 * node:fs and node:path are allowed in this CLI file only; the kernel itself
 * stays Workers-safe.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { SCHEMA_VERSION } from "../policy.js";
import { verifyOffline, type Diff, type VerifyReport } from "../verify.js";

export interface VerifyIo {
  stdout: (line: string) => void;
  stderr: (line: string) => void;
}

const USAGE = "usage: verify <entry.json> <log-bundle.json>";

/** A short, one-line cause: an errno where there is one, else the first line. */
function reasonOf(error: unknown): string {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code: unknown }).code;
    if (typeof code === "string") return code;
  }
  if (error instanceof Error) {
    const first = error.message.split("\n")[0];
    if (first !== undefined && first.length > 0) return first;
  }
  return "unknown error";
}

type ReadResult =
  | { ok: true; value: unknown }
  | { ok: false; message: string };

/** One file, read and parsed. Both failures name the file and say which it was. */
async function readJson(path: string): Promise<ReadResult> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    return { ok: false, message: `${path}: cannot read: ${reasonOf(error)}` };
  }
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch (error) {
    return { ok: false, message: `${path}: not JSON: ${reasonOf(error)}` };
  }
}

/**
 * One diff, on one line: what was checked, where, and why it failed, with the
 * two values only when there are values to show.
 */
function formatDiff(diff: Diff): string {
  const head = `${diff.check} ${diff.field} ${diff.reason}`;
  if (diff.expected === null && diff.actual === null) return head;
  return `${head} expected=${JSON.stringify(diff.expected)} actual=${JSON.stringify(diff.actual)}`;
}

/**
 * Check the entry at `entryPath` against the log bundle at `bundlePath`.
 *
 * Returns the process's exit code: 0 clean, 1 with named diffs (or an
 * unreadable file).
 */
export async function verify(
  entryPath: string,
  bundlePath: string,
  io: VerifyIo,
): Promise<number> {
  const entry = await readJson(entryPath);
  if (!entry.ok) {
    io.stderr(entry.message);
    return 1;
  }
  const bundle = await readJson(bundlePath);
  if (!bundle.ok) {
    io.stderr(bundle.message);
    return 1;
  }

  // The kernel answers a malformed file with a diff, so this catch is the belt
  // to its braces: if it ever rejects, the caller still gets one named line.
  let report: VerifyReport;
  try {
    report = await verifyOffline(entry.value, bundle.value);
  } catch (error) {
    io.stderr(`${entryPath}: cannot verify: ${reasonOf(error)}`);
    return 1;
  }
  // Which rules this run held the entry to (decision D-071). A reader checking
  // a v0.6 record with a v0.7 verifier is told what it was checked against
  // before it is told the verdict, so "unsupported_schema_version" reads as an
  // answer about versions rather than as a mystery.
  io.stdout(`schema ${SCHEMA_VERSION}`);

  if (report.ok) {
    io.stdout(`ok ${report.entry_id}`);
    return 0;
  }

  for (const diff of report.diffs) {
    io.stdout(formatDiff(diff));
  }
  io.stdout(`${report.diffs.length} diff(s)`);
  return 1;
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const entryPath = process.argv[2];
  const bundlePath = process.argv[3];
  if (entryPath === undefined || bundlePath === undefined) {
    console.error(USAGE);
    process.exit(2);
  }
  process.exit(
    await verify(entryPath, bundlePath, {
      stdout: (line: string) => console.log(line),
      stderr: (line: string) => console.error(line),
    }),
  );
}
/* c8 ignore stop */

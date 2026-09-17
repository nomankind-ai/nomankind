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
 * A bounded bundle (decision D-120) is a third answer that is neither a pass
 * nor a fault on its own: the file carries this entry's events, a proof each
 * against the seal that covers them, and the seals' own links, and not the rest
 * of the log. It checks out or it does not exactly as a full bundle does, and
 * one line says which checks had no inputs in it, so an `ok` is read as the
 * sentence it is rather than as the wider one.
 *
 * One thing is added to the diffs and nothing is taken away: a hand-edited
 * content field fails the signature, the core and the derived view, and the
 * three lines are one fault. They are all printed, the count still counts them
 * all, and one `note:` line after the count says what they add up to. The
 * kernel decides when it applies (`oneEditExplains`).
 *
 * node:fs and node:path are allowed in this CLI file only; the kernel itself
 * stays Workers-safe.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { SCHEMA_VERSION } from "../policy.js";
import {
  oneEditExplains,
  verifyOffline,
  verifySignedCertificate,
  type Diff,
  type VerifyReport,
} from "../verify.js";

export interface VerifyIo {
  stdout: (line: string) => void;
  stderr: (line: string) => void;
}

const USAGE =
  "usage: verify <entry.json> <log-bundle.json>\n" +
  "       verify --certificate <certificate.json> [--issuer <agent id>]";

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

  // What a bounded bundle bought and what it cost (decision D-120). Before the
  // verdict, because it changes what the verdict means: `ok` over a bounded
  // bundle says this entry's events were sealed and its signatures hold, and
  // does not say the log they came out of folds to this entry. Printed only for
  // a bounded bundle, so the full path's two lines are what they have always
  // been.
  if (report.bounded) {
    io.stdout(`bounded not_run=${report.not_run.join(",")}`);
  }

  if (report.ok) {
    io.stdout(`ok ${report.entry_id}`);
    return 0;
  }

  for (const diff of report.diffs) {
    io.stdout(formatDiff(diff));
  }
  io.stdout(`${report.diffs.length} diff(s)`);

  // One edit to a content field fails the signature, the core and the derived
  // view, which is three lines above and one fault underneath. The lines and
  // the count stay as they are — each check really did fail — and this says
  // what they add up to, so a reader does not go looking for three causes. The
  // kernel decides it (src/verify.ts); nothing is judged here.
  if (oneEditExplains(report)) {
    io.stdout(
      "note: one edit to the core would account for the signature and hash differences above",
    );
  }
  return 1;
}

/**
 * Check one standing certificate (decisions D-127 and D-130).
 *
 * `npm run verify -- --certificate <file> [--issuer <agent id>]`. The exit code
 * is the answer, exactly as the entry check's is: 0 when the signature holds, 1
 * when it does not or the file cannot be read.
 *
 * The issuer is printed whether or not it was given, because that is the line
 * the reader acts on: a certificate names the key that signed it, and what
 * makes it nomankind's is that the key is the record's own sealing agent, which
 * the reader compares for themselves. Given `--issuer`, the check also refuses
 * a document some other key signed, so a mistake is an exit code and not a line
 * somebody has to notice.
 */
export async function verifyCertificateFile(
  certificatePath: string,
  issuer: string | null,
  io: VerifyIo,
): Promise<number> {
  const file = await readJson(certificatePath);
  if (!file.ok) {
    io.stderr(file.message);
    return 1;
  }

  const report = await verifySignedCertificate(
    file.value,
    issuer ?? undefined,
  );
  io.stdout(`issuer ${report.issuer ?? "(none)"}`);
  if (report.subject !== null) {
    io.stdout(
      `subject ${report.subject} standing ${report.standing ?? "?"} ${
        report.tier ?? "?"
      } at position ${report.sealed_position ?? "?"}`,
    );
  }
  if (!report.ok) {
    io.stdout(`certificate ${report.reason ?? "bad_signature"}`);
    return 1;
  }
  io.stdout("ok certificate");
  return 0;
}

/** What one invocation asks for, or null when the arguments are not one. */
export interface CertificatePlan {
  readonly certificatePath: string;
  readonly issuer: string | null;
}

/**
 * Read a `--certificate` invocation, or null when this is not one.
 *
 * Refuses rather than guesses, exactly as the export's parser does: an unknown
 * flag, a repeated one, or a value that looks like another flag is a command
 * nobody meant to type.
 */
export function certificatePlan(
  args: readonly string[],
): CertificatePlan | null {
  if (args[0] !== "--certificate") return null;
  const certificatePath = args[1];
  if (certificatePath === undefined || certificatePath.startsWith("--")) {
    return null;
  }
  const rest = args.slice(2);
  if (rest.length === 0) return { certificatePath, issuer: null };
  if (rest.length !== 2 || rest[0] !== "--issuer") return null;
  const issuer = rest[1];
  if (issuer === undefined || issuer.startsWith("--")) return null;
  return { certificatePath, issuer };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const io: VerifyIo = {
    stdout: (line: string) => console.log(line),
    stderr: (line: string) => console.error(line),
  };
  const args = process.argv.slice(2);

  if (args[0] === "--certificate") {
    const plan = certificatePlan(args);
    if (plan === null) {
      console.error(USAGE);
      process.exit(2);
    }
    process.exit(
      await verifyCertificateFile(plan.certificatePath, plan.issuer, io),
    );
  }

  const entryPath = args[0];
  const bundlePath = args[1];
  if (entryPath === undefined || bundlePath === undefined) {
    console.error(USAGE);
    process.exit(2);
  }
  process.exit(await verify(entryPath, bundlePath, io));
}
/* c8 ignore stop */

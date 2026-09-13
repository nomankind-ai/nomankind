/**
 * `AbortSignal.timeout` must not be called anywhere under src/.
 *
 * The demo deployment's alarm spent thirty seconds of wall time against
 * forty-six milliseconds of CPU on a run that had nothing to do. The shape
 * behind it: `AbortSignal.timeout(ms)` schedules a timer that cannot be
 * cancelled, and on workerd a pending timer keeps the invocation alive until it
 * fires, so a call that came back in fifty milliseconds still held the whole
 * window open. Every outbound call goes through src/adapters/timeout.ts's
 * `withDeadline` instead, whose timer is cleared the moment the call is done.
 *
 * That is the kind of rule a linter would hold, and this repository has no
 * eslint: decision D-011 keeps the dependency baseline to what the kernel needs
 * to build and run on Workers, and one grep over the sources is cheaper than a
 * toolchain. So it is a test, and it fails the same way a lint rule would.
 *
 * Only the call form is refused. The comments above quote the name to say why
 * the helper exists, and a rule that could not tell a warning from a use would
 * make those comments unwritable — so a line that is a comment is skipped.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/** The repository's sources, resolved from this file so the cwd does not matter. */
const SRC = fileURLToPath(new URL("../src/", import.meta.url));

/** What a use looks like: the name with its opening parenthesis. */
const CALL = "AbortSignal.timeout(";

/** Every .ts file under a directory, recursively, as absolute paths. */
function sourcesUnder(directory: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...sourcesUnder(path));
    else if (entry.name.endsWith(".ts")) found.push(path);
  }
  return found.sort();
}

/** Whether the line is prose rather than code. */
function isComment(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.startsWith("*") ||
    trimmed.startsWith("//") ||
    trimmed.startsWith("/*")
  );
}

describe("the timeout that cannot be cleared", () => {
  it("is called nowhere under src/", () => {
    const offences: string[] = [];
    const files = sourcesUnder(SRC);
    for (const file of files) {
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((line, index) => {
        if (!line.includes(CALL) || isComment(line)) return;
        offences.push(`${file.slice(SRC.length)}:${index + 1}: ${line.trim()}`);
      });
    }
    // Named rather than counted: a failure here should say which line to move
    // onto `withDeadline`.
    expect(offences).toEqual([]);
    // And the scan itself is worth a witness: a walk that found nothing would
    // pass this rule while holding nothing at all.
    expect(files.length).toBeGreaterThan(20);
  });

  it("is still allowed to be named in a comment", () => {
    // The adapters explain the choice in prose, and this file's rule must not
    // be the reason they stop.
    const timeout = readFileSync(join(SRC, "adapters/timeout.ts"), "utf8");
    expect(timeout.includes(CALL)).toBe(true);
  });
});

/**
 * The one script (src/cli/verify.ts).
 *
 * The exit code is the whole answer — 0 clean, 1 with named diffs — so every
 * test here asserts the code first and the lines second. A stranger's file is
 * data: a missing file and a file full of garbage each get one line on stderr,
 * never a stack trace and never a half-printed report.
 */

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { verify } from "../src/cli/verify.js";

const FIXTURE_DIR = join(import.meta.dirname, "fixtures", "verify");
const ENTRY = join(FIXTURE_DIR, "verified-entry.json");
const DRAFT = join(FIXTURE_DIR, "draft-entry.json");
const LOG = join(FIXTURE_DIR, "log.json");

let directory: string;

/** Collects both streams separately, so a test can tell them apart. */
function capture(): {
  out: string[];
  err: string[];
  io: { stdout: (line: string) => void; stderr: (line: string) => void };
} {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    io: {
      stdout: (line: string) => out.push(line),
      stderr: (line: string) => err.push(line),
    },
  };
}

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "nomankind-verify-"));
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

describe("verify (the one script)", () => {
  it("exits 0 and prints one ok line for the sealed entry", async () => {
    const { out, err, io } = capture();
    expect(await verify(ENTRY, LOG, io)).toBe(0);
    const entry = JSON.parse(await readFile(ENTRY, "utf8")) as { id: string };
    expect(out).toEqual([`ok ${entry.id}`]);
    expect(err).toEqual([]);
  });

  it("exits 0 for the unsealed draft too", async () => {
    const { out, err, io } = capture();
    expect(await verify(DRAFT, LOG, io)).toBe(0);
    const entry = JSON.parse(await readFile(DRAFT, "utf8")) as { id: string };
    expect(out).toEqual([`ok ${entry.id}`]);
    expect(err).toEqual([]);
  });

  it("exits 1 and names every diff, with a count last", async () => {
    const tampered = join(directory, "tampered-entry.json");
    const entry = JSON.parse(await readFile(ENTRY, "utf8")) as Record<
      string,
      unknown
    >;
    entry["status"] = "draft";
    await writeFile(tampered, JSON.stringify(entry, null, 2), "utf8");

    const { out, err, io } = capture();
    expect(await verify(tampered, LOG, io)).toBe(1);
    expect(err).toEqual([]);
    expect(out.length).toBeGreaterThan(1);

    const last = out[out.length - 1]!;
    expect(last).toBe(`${out.length - 1} diff(s)`);
    for (const line of out.slice(0, -1)) {
      // "<check> <field> <reason>", then the two values when there are any.
      expect(line).toMatch(
        /^[a-z]+ \/\S* [a-z0-9_]+( expected=.* actual=.*)?$/,
      );
      expect(line).not.toContain("\n");
    }
    expect(out.some((line) => line.startsWith("derived /status "))).toBe(true);
  });

  it("exits 1 with one stderr line and no stdout when a file is missing", async () => {
    const { out, err, io } = capture();
    const missing = join(directory, "not-here.json");
    expect(await verify(missing, LOG, io)).toBe(1);
    expect(out).toEqual([]);
    expect(err).toHaveLength(1);
    expect(err[0]).toContain(missing);
    expect(err[0]).not.toContain("at ");
  });

  it("exits 1 with one stderr line when a file is not JSON", async () => {
    const broken = join(directory, "broken.json");
    await writeFile(broken, "{ not json at all", "utf8");
    const { out, err, io } = capture();
    expect(await verify(ENTRY, broken, io)).toBe(1);
    expect(out).toEqual([]);
    expect(err).toHaveLength(1);
    expect(err[0]).toContain(broken);
    expect(err[0]).toContain("not JSON");
  });

  it("is reachable as `npm run verify`", async () => {
    const manifest = JSON.parse(
      await readFile(join(import.meta.dirname, "..", "package.json"), "utf8"),
    ) as { scripts: Record<string, string> };
    expect(manifest.scripts["verify"]).toBe(
      "npm run build --silent && node dist/cli/verify.js",
    );
  });
});

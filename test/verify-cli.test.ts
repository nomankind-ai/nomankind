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
import { SCHEMA_VERSION } from "../src/policy.js";
import {
  oneEditExplains,
  type Diff,
  type VerifyReport,
} from "../src/verify.js";

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
    // Decision D-071: the schema version this run checked against, first.
    expect(out).toEqual([`schema ${SCHEMA_VERSION}`, `ok ${entry.id}`]);
    expect(err).toEqual([]);
  });

  it("exits 0 for the unsealed draft too", async () => {
    const { out, err, io } = capture();
    expect(await verify(DRAFT, LOG, io)).toBe(0);
    const entry = JSON.parse(await readFile(DRAFT, "utf8")) as { id: string };
    expect(out).toEqual([`schema ${SCHEMA_VERSION}`, `ok ${entry.id}`]);
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

    expect(out[0]).toBe(`schema ${SCHEMA_VERSION}`);
    const diffs = out.slice(1);
    const last = diffs[diffs.length - 1]!;
    expect(last).toBe(`${diffs.length - 1} diff(s)`);
    for (const line of diffs.slice(0, -1)) {
      // "<check> <field> <reason>", then the two values when there are any.
      expect(line).toMatch(
        /^[a-z]+ \/\S* [a-z0-9_]+( expected=.* actual=.*)?$/,
      );
      expect(line).not.toContain("\n");
    }
    expect(out.some((line) => line.startsWith("derived /status "))).toBe(true);
  });

  it("says when one edit to the core accounts for the rest", async () => {
    // One hand-edited content field fails three checks — the signature is over
    // the core, the log sealed the core as it was signed, and the derived view
    // is recomputed from it — and a reader who counts three goes looking for
    // three causes.
    const edited = join(directory, "edited-claim-entry.json");
    const entry = JSON.parse(await readFile(ENTRY, "utf8")) as Record<
      string,
      unknown
    >;
    entry["claim"] = `${String(entry["claim"])} (edited)`;
    await writeFile(edited, JSON.stringify(entry, null, 2), "utf8");

    const { out, err, io } = capture();
    expect(await verify(edited, LOG, io)).toBe(1);
    expect(err).toEqual([]);

    // The diffs are all still there, and so is the count over all of them.
    expect(out.some((line) => line.startsWith("signature /signature "))).toBe(
      true,
    );
    expect(out.some((line) => line.startsWith("core /claim "))).toBe(true);
    const count = out.findIndex((line) => line.endsWith(" diff(s)"));
    expect(out[count]).toBe(`${count - 1} diff(s)`);
    // And the one sentence that says what they add up to, last.
    expect(out[out.length - 1]).toBe(
      "note: one edit to the core would account for the signature and hash differences above",
    );
    expect(out).toHaveLength(count + 2);
  });

  it("says nothing of the sort when the signature still holds", async () => {
    // A derived field edited on its own is a difference with a good signature
    // behind it, which is a question about the log and not an edit to the core.
    // Half the shape must not print the note.
    const derived = join(directory, "edited-status-entry.json");
    const entry = JSON.parse(await readFile(ENTRY, "utf8")) as Record<
      string,
      unknown
    >;
    entry["status"] = "draft";
    await writeFile(derived, JSON.stringify(entry, null, 2), "utf8");

    const { out, io } = capture();
    expect(await verify(derived, LOG, io)).toBe(1);
    expect(out.some((line) => line.startsWith("note:"))).toBe(false);
  });

  it("needs both halves before it says anything", () => {
    // The predicate, asked directly: the CLI can only reach the both-present
    // shape through a real edit, and each half alone has to be pinned too.
    const report = (diffs: Diff[]): VerifyReport => ({
      ok: false,
      entry_id: "nmk_0",
      diffs,
      withheld: 0,
      bounded: false,
      not_run: [],
    });
    const signature: Diff = {
      check: "signature",
      field: "/signature",
      expected: null,
      actual: null,
      reason: "bad_signature",
    };
    const core: Diff = {
      check: "core",
      field: "/claim",
      expected: "before",
      actual: "after",
      reason: "mismatch",
    };
    const snapshot: Diff = {
      check: "snapshot",
      field: "/snapshot_hash",
      expected: "sha256:aaa",
      actual: "sha256:bbb",
      reason: "mismatch",
    };

    expect(oneEditExplains(report([signature, core]))).toBe(true);
    expect(oneEditExplains(report([signature, snapshot]))).toBe(true);
    // A bad signature with nothing behind it is a question about the key, and
    // a mismatch with a good signature is a question about the log. Neither is
    // the one edit this names.
    expect(oneEditExplains(report([signature]))).toBe(false);
    expect(oneEditExplains(report([snapshot]))).toBe(false);
    expect(oneEditExplains(report([core]))).toBe(false);
    expect(oneEditExplains(report([]))).toBe(false);
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

/**
 * The committed fixtures: the paper's two files, on disk.
 *
 * Goals and non-goals, goal 4: "anyone can check the proof offline with two
 * files and one script". These tests are the stranger. They read the three
 * static files in test/fixtures/verify/ exactly as a stranger would — no world
 * is built, no key is held — and check that the verifier calls them clean; then
 * they hand-edit one thing in memory and watch it named.
 *
 * The files themselves are written by the guarded generator at the top, so no
 * derived field is ever authored by hand:
 *
 *   NOMANKIND_WRITE_FIXTURES=1 npm test -- verify-fixtures
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { base64Decode, base64Encode } from "../src/encoding.js";
import { decodeProof, encodeProof } from "../src/merkle.js";
import { verifyOffline, type VerifyReport } from "../src/verify.js";
import { buildVerifyWorld } from "./helpers/verify-world.js";

type Json = Record<string, unknown>;

const FIXTURE_DIR = join(import.meta.dirname, "fixtures", "verify");
const SCHEMA_PATH = join(
  import.meta.dirname,
  "..",
  "schema",
  "nomankind-entry-schema.json",
);

/** The clock the fixtures are frozen at, so as_of and every window are stable. */
const FIXED_NOW = "2026-09-10T00:00:00Z";

async function writeFixture(name: string, value: unknown): Promise<void> {
  await writeFile(
    join(FIXTURE_DIR, name),
    `${JSON.stringify(value, null, 2)}\n`,
    "utf8",
  );
}

async function readFixture(name: string): Promise<Json> {
  return JSON.parse(await readFile(join(FIXTURE_DIR, name), "utf8")) as Json;
}

/** The entry, the bundle, and a deep copy of each so a test's edits stay its own. */
async function files(
  entryName = "verified-entry.json",
): Promise<{ entry: Json; bundle: Json }> {
  return {
    entry: await readFixture(entryName),
    bundle: await readFixture("log.json"),
  };
}

function expectDiff(report: VerifyReport, check: string, field: string): void {
  expect(report.ok).toBe(false);
  expect(
    report.diffs.filter((diff) => diff.check === check && diff.field === field),
  ).not.toHaveLength(0);
}

describe("verify fixtures (generation)", () => {
  // Guarded: the committed files are the fixture, and a test run must not
  // rewrite them (fresh keys every call would churn the repository on every
  // run). Regenerate deliberately, with NOMANKIND_WRITE_FIXTURES=1.
  it.skipIf(!process.env["NOMANKIND_WRITE_FIXTURES"])(
    "writes log.json and the two entry files",
    async () => {
      const world = await buildVerifyWorld({ now: FIXED_NOW });
      await mkdir(FIXTURE_DIR, { recursive: true });
      await writeFixture("log.json", world.bundle);
      await writeFixture("verified-entry.json", world.entry);
      await writeFixture("draft-entry.json", world.draftEntry);

      // What was just written has to verify, or it is not a fixture.
      expect((await verifyOffline(world.entry, world.bundle)).ok).toBe(true);
      expect((await verifyOffline(world.draftEntry, world.bundle)).ok).toBe(true);
    },
  );
});

describe("verify fixtures (the two files, clean)", () => {
  it("verifies the sealed entry against the committed log with no diffs", async () => {
    const { entry, bundle } = await files();
    const report = await verifyOffline(entry, bundle);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.entry_id).toBe(entry["id"]);
  });

  it("verifies the draft entry, whose seal is explicitly null", async () => {
    const { entry, bundle } = await files("draft-entry.json");
    const report = await verifyOffline(entry, bundle);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(entry["seal"]).toBeNull();
    expect(entry["status"]).toBe("draft");
  });

  it("gives the sealed entry a verified status and a 1F916 seal", async () => {
    const entry = await readFixture("verified-entry.json");
    expect(entry["status"]).toBe("verified");
    const seal = entry["seal"] as Json;
    expect(seal).not.toBeNull();
    expect(seal["log"]).toBe("1F916");
  });

  it("carries every derived field explicitly on both entries, null included", async () => {
    const schema = JSON.parse(await readFile(SCHEMA_PATH, "utf8")) as {
      properties: Record<string, unknown>;
    };
    const expected = Object.keys(schema.properties).sort();
    for (const name of ["verified-entry.json", "draft-entry.json"]) {
      const entry = await readFixture(name);
      expect(Object.keys(entry).sort()).toEqual(expected);
    }
  });

  it("carries the explicitly null derived fields the draft has nothing to fill", async () => {
    const entry = await readFixture("draft-entry.json");
    for (const key of ["seal", "confidence", "superseded_by", "overturned_by"]) {
      expect(entry).toHaveProperty(key);
      expect(entry[key]).toBeNull();
    }
  });
});

describe("verify fixtures (one edit at a time)", () => {
  it("names a hand-edited status", async () => {
    const { entry, bundle } = await files();
    entry["status"] = "draft";
    expectDiff(await verifyOffline(entry, bundle), "derived", "/status");
  });

  it("names an edited claim as a bad author signature", async () => {
    const { entry, bundle } = await files();
    entry["claim"] = "gpt-5 input price is $0.25 per million tokens";
    expectDiff(await verifyOffline(entry, bundle), "signature", "/signature");
  });

  it("names a dropped approver", async () => {
    const { entry, bundle } = await files();
    const approvers = entry["approvers"] as unknown[];
    expect(approvers.length).toBeGreaterThan(1);
    entry["approvers"] = approvers.slice(1);
    expectDiff(await verifyOffline(entry, bundle), "derived", "/approvers");
  });

  it("names a broken hash chain", async () => {
    const { entry, bundle } = await files();
    const events = bundle["events"] as Json[];
    const payload = events[0]!["payload"] as Json;
    payload["operator"] = "op_forged";
    const report = await verifyOffline(entry, bundle);
    expect(report.ok).toBe(false);
    expect(report.diffs.some((diff) => diff.check === "chain")).toBe(true);
  });

  it("names an edited archived capture", async () => {
    const { entry, bundle } = await files();
    const captures = bundle["captures"] as Record<string, Json>;
    const key = entry["snapshot_hash"] as string;
    const capture = captures[key]!;
    const text = new TextDecoder().decode(
      base64Decode(capture["body_base64"] as string),
    );
    const edited = text.replace("$2.50", "$2.60");
    expect(edited).not.toBe(text);
    capture["body_base64"] = base64Encode(new TextEncoder().encode(edited));
    expectDiff(await verifyOffline(entry, bundle), "snapshot", "/snapshot_hash");
  });

  it("names a broken inclusion proof", async () => {
    const { entry, bundle } = await files();
    const seal = entry["seal"] as Json;
    const proof = decodeProof(seal["inclusion_proof"] as string);
    expect(proof).not.toBeNull();
    expect(proof!.path.length).toBeGreaterThan(0);
    const step = proof!.path[0]!;
    const last = step.slice(-1);
    proof!.path[0] = `${step.slice(0, -1)}${last === "0" ? "1" : "0"}`;
    seal["inclusion_proof"] = encodeProof(proof!);
    expectDiff(await verifyOffline(entry, bundle), "seal", "/seal/inclusion_proof");
  });

  it("names a fake seal on the unsealed draft", async () => {
    const { entry, bundle } = await files("draft-entry.json");
    const real = (await readFixture("verified-entry.json"))["seal"] as Json;
    entry["seal"] = { ...real };
    expectDiff(await verifyOffline(entry, bundle), "derived", "/seal");
  });
});

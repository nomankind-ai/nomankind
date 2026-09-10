/**
 * M9 end to end: the paper's promise, told once, through the public surface.
 *
 * Whitepaper, Goals and non-goals, goal 4: "anyone can check the proof offline
 * with two files and one script." So this test does exactly that and nothing
 * else — it builds a whole world, writes the two files to disk, and runs the
 * script on them the way a stranger would. Everything it imports from the
 * kernel comes through the package index, because that is the surface a
 * stranger has.
 *
 * Then it edits one field in each file, in turn, and watches the script name
 * it: an entry whose status was raised by hand, and a log whose event payload
 * was rewritten under a hash that no longer covers it.
 */

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { verifyOffline, verifyRecordSignature } from "../src/index.js";
import { verify } from "../src/cli/verify.js";
import { buildVerifyWorld, type VerifyWorld } from "./helpers/verify-world.js";
import { SCHEMA_VERSION } from "../src/policy.js";

type Json = Record<string, unknown>;

let directory: string;
let world: VerifyWorld;
let entryPath: string;
let draftPath: string;
let bundlePath: string;

/** Both streams, kept apart, exactly as the CLI's own tests collect them. */
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

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function readJson(path: string): Promise<Json> {
  return JSON.parse(await readFile(path, "utf8")) as Json;
}

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "nomankind-m9-"));
  world = await buildVerifyWorld();
  entryPath = join(directory, "entry.json");
  draftPath = join(directory, "draft.json");
  bundlePath = join(directory, "log.json");
  await writeJson(entryPath, world.entry);
  await writeJson(draftPath, world.draftEntry);
  await writeJson(bundlePath, world.bundle);
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

describe("M9: two files and one script", () => {
  it("checks the verified entry against the log beside it", async () => {
    const { out, err, io } = capture();
    expect(await verify(entryPath, bundlePath, io)).toBe(0);
    // Decision D-071: the schema version this run checked against, first.
    expect(out).toEqual([`schema ${SCHEMA_VERSION}`, `ok ${world.entryId}`]);
    expect(err).toEqual([]);
  });

  it("checks the unsealed draft the same way", async () => {
    const { out, err, io } = capture();
    expect(await verify(draftPath, bundlePath, io)).toBe(0);
    expect(out).toEqual([`schema ${SCHEMA_VERSION}`, `ok ${world.draftEntryId}`]);
    expect(err).toEqual([]);
  });

  it("names a status raised by hand in the entry file", async () => {
    const tampered = join(directory, "tampered-entry.json");
    const entry = await readJson(entryPath);
    entry["status"] = "draft";
    await writeJson(tampered, entry);

    const { out, err, io } = capture();
    expect(await verify(tampered, bundlePath, io)).toBe(1);
    expect(err).toEqual([]);
    expect(out.some((line) => line.startsWith("derived /status mismatch"))).toBe(
      true,
    );
    expect(out[0]).toBe(`schema ${SCHEMA_VERSION}`);
    expect(out[out.length - 1]).toBe(`${out.length - 2} diff(s)`);
  });

  it("names an event payload rewritten in the log file", async () => {
    const tampered = join(directory, "tampered-log.json");
    const bundle = await readJson(bundlePath);
    const events = bundle["events"] as Json[];
    const target = events.find((event) => event["type"] === "operator_trusted")!;
    (target["payload"] as Json)["operator"] = "op_impostor";
    await writeJson(tampered, bundle);

    const { out, err, io } = capture();
    expect(await verify(entryPath, tampered, io)).toBe(1);
    expect(err).toEqual([]);
    expect(
      out.some((line) => line.startsWith(`chain /events/${target["seq"] as number} `)),
    ).toBe(true);
  });

  it("reaches the kernel's two verifications through the package index", async () => {
    expect(typeof verifyOffline).toBe("function");
    expect(typeof verifyRecordSignature).toBe("function");

    const report = await verifyOffline(world.entry, world.bundle);
    expect(report.ok).toBe(true);
    expect(report.entry_id).toBe(world.entryId);

    const validation = world.bundle.events.find(
      (event) => event.type === "validation",
    )!;
    const payload = validation.payload as Json;
    expect(
      await verifyRecordSignature(
        world.entryId,
        "validation",
        payload["record"],
        payload["signature"] as string,
      ),
    ).toBe(true);
  });
});

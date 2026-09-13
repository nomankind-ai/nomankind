/**
 * The offline verifier inside the release window (decision D-100).
 *
 * The QA of 2026-09-12: a reader with no key exports the events their window has
 * not opened as hash lines — the payload null and `withheld: true` beside it —
 * and the verifier called every one of them a malformed event, which made the
 * bundle unreadable and suppressed every check after it. So no keyless export of
 * a log with anything still inside the window verified at all, against D-100's
 * promise that the released record verifies free.
 *
 * What these tests stand on is the rule the mirror verifier already holds: a
 * hash line is an event like any other for the chain and the seal, it is read
 * for nothing else, and it is counted rather than named as a difference. The
 * proof is still proof — an edited hash line fails, by its links or by its
 * seal's root — and a released export is checked exactly as it always was.
 *
 * The keyless view is built here the way `GET /events` builds it
 * (src/worker/events.ts): per event, by the seal that covers it, against this
 * reader's own clock.
 */

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { verify } from "../src/cli/verify.js";
import type { Event } from "../src/events.js";
import { SCHEMA_VERSION } from "../src/policy.js";
import type { Sidecar } from "../src/derive.js";
import {
  isReleased,
  releaseDateOf,
  withholdEntry,
  withholdEvent,
} from "../src/release.js";
import { buildSeal } from "../src/seal.js";
import { verifyOffline, type LogBundle } from "../src/verify.js";
import { buildVerifyWorld, type VerifyWorld } from "./helpers/verify-world.js";

/**
 * The instant the tail of the log is sealed: a month after the world's own
 * events, so a clock can stand on either side of that seal's window while the
 * first seal is long since public.
 */
const TAIL_SEALED_AT = "2026-10-10T00:00:00Z";

/** A reader's clock two days after the tail seal: inside its window. */
const INSIDE_THE_WINDOW = "2026-10-12T00:00:00Z";

/** A reader's clock long after it: nothing of this log is withheld any more. */
const AFTER_THE_WINDOW = "2026-12-01T00:00:00Z";

/**
 * The world, with its unsealed tail sealed too.
 *
 * The helper seals everything up to the verified entry's decisions and leaves
 * the draft submitted after it unsealed. A second seal over that tail is what
 * gives this file a hash line that some seal's Merkle root is over, which is
 * what makes an edited one catchable — and is what a live log looks like, where
 * the sweep seals the head on a cadence and the newest seal is always the one
 * inside the window.
 */
async function sealedWorld(
  now: string,
): Promise<{ world: VerifyWorld; bundle: LogBundle }> {
  const world = await buildVerifyWorld({ now });
  const first = world.bundle.seals[0]!;
  const tail = await buildSeal(world.bundle.events, first, {
    now: TAIL_SEALED_AT,
  });
  if (!tail.ok) throw new Error(`sealedWorld: buildSeal ${tail.reason}`);
  return {
    world,
    bundle: { ...world.bundle, seals: [...world.bundle.seals, tail.seal] },
  };
}

/**
 * The bundle as a reader with no key is served it: every event whose covering
 * seal has not released yet as a hash line, exactly as `GET /events` answers a
 * free reader (src/worker/events.ts).
 */
function keyless(bundle: LogBundle, now: Date): LogBundle {
  return {
    ...bundle,
    events: bundle.events.map((event) => {
      const seal = bundle.seals.find(
        (candidate) =>
          event.seq >= candidate.first_seq && event.seq <= candidate.last_seq,
      );
      return isReleased(seal === undefined ? null : seal.sealed_at, now)
        ? event
        : (withholdEvent(event) as unknown as Event);
    }),
  };
}

/**
 * A sidecar for `withholdEntry`, which passes it through untouched: the entry
 * file the export writes is the proof alone, and no check here reads one.
 */
const SIDECAR = {} as unknown as Sidecar;

/** The hash lines in a bundle, by seq. */
function hashLines(bundle: LogBundle): Event[] {
  return bundle.events.filter(
    (event) => (event as unknown as { withheld?: unknown }).withheld === true,
  );
}

/** One hex character of a hash, flipped: the same shape, a different digest. */
function flip(hash: string): string {
  const last = hash.slice(-1);
  return `${hash.slice(0, -1)}${last === "0" ? "1" : "0"}`;
}

describe("the offline verifier, inside the release window", () => {
  it("verifies a keyless export whose newest seal has not released", async () => {
    const { world, bundle } = await sealedWorld(INSIDE_THE_WINDOW);
    const free = keyless(bundle, new Date(INSIDE_THE_WINDOW));

    // The premise: this is the free view, and it really is short of something.
    expect(hashLines(free).length).toBeGreaterThan(0);

    const report = await verifyOffline(world.entry, free);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.entry_id).toBe(world.entryId);
    // Counted, and counted exactly: the report says how much of the log this
    // reader was handed as proof alone.
    expect(report.withheld).toBe(hashLines(free).length);
  });

  it("never calls a hash line a malformed event, so the later checks still run", async () => {
    const { world, bundle } = await sealedWorld(INSIDE_THE_WINDOW);
    const free = keyless(bundle, new Date(INSIDE_THE_WINDOW));

    // The QA's own symptom: a bundle diff on a hash line, which stopped the run
    // before the chain, the seals and the derivation were ever asked.
    const report = await verifyOffline(world.entry, free);
    expect(report.diffs.filter((diff) => diff.check === "bundle")).toEqual([]);

    // And the proof of that: a hand-edited status in the same export is still
    // named, which it cannot be if the run stops at the bundle.
    const edited = { ...(world.entry as unknown as Record<string, unknown>) };
    edited["status"] = "draft";
    const second = await verifyOffline(edited, free);
    expect(second.ok).toBe(false);
    expect(
      second.diffs.some(
        (diff) => diff.check === "derived" && diff.field === "/status",
      ),
    ).toBe(true);
  });

  it("fails a hash line whose hash was edited, by its seal", async () => {
    const { world, bundle } = await sealedWorld(INSIDE_THE_WINDOW);
    const free = keyless(bundle, new Date(INSIDE_THE_WINDOW));
    const line = hashLines(free)[0]!;
    // Nobody can recompute a withheld payload's hash, so the seal's Merkle root
    // is what holds it: the leaf moved, the root no longer follows.
    const tampered = free.events.map((event) =>
      event.seq === line.seq ? { ...event, hash: flip(event.hash) } : event,
    );

    const report = await verifyOffline(world.entry, { ...free, events: tampered });
    expect(report.ok).toBe(false);
    expect(
      report.diffs.some(
        (diff) => diff.check === "seals" || diff.check === "chain",
      ),
    ).toBe(true);
  });

  it("fails a hash line unlinked from the event before it", async () => {
    const { world, bundle } = await sealedWorld(INSIDE_THE_WINDOW);
    const free = keyless(bundle, new Date(INSIDE_THE_WINDOW));
    const line = hashLines(free)[0]!;
    const tampered = free.events.map((event) =>
      event.seq === line.seq
        ? { ...event, prev_hash: flip(event.prev_hash as string) }
        : event,
    );

    const report = await verifyOffline(world.entry, { ...free, events: tampered });
    expect(report.ok).toBe(false);
    expect(
      report.diffs.some(
        (diff) => diff.check === "chain" && diff.reason === "bad_prev_hash",
      ),
    ).toBe(true);
  });

  it("answers one named item when the entry file is itself withheld", async () => {
    const { world, bundle } = await sealedWorld(INSIDE_THE_WINDOW);
    const free = keyless(bundle, new Date(INSIDE_THE_WINDOW));

    // The file `npm run export` writes for a reader with no entitlement: the
    // proof, every content field null, every proof field untouched. Built here
    // out of src/release.ts's own function, so nothing about the shape is this
    // test's invention. The sidecar is passed through untouched and is not part
    // of either file.
    const held = await withholdEntry(world.entry, SIDECAR, "");

    const report = await verifyOffline(held.proof, free);

    // One item, not the eight true-but-useless differences the ordinary checks
    // used to find in it -- five schema_violation for the nulled strings,
    // bad_signature, not_submitted, capture_missing.
    expect(report.ok).toBe(false);
    expect(report.entry_id).toBe(world.entryId);
    expect(report.diffs.length).toBe(1);
    expect(report.diffs[0]).toEqual({
      check: "window",
      field: "/claim",
      expected: releaseDateOf(
        (world.entry as unknown as { seal: { sealed_at: string } }).seal
          .sealed_at,
      ),
      actual: null,
      reason: "entry_withheld",
    });
  });

  it("still names an entry somebody merely broke", async () => {
    const { world, bundle } = await sealedWorld(INSIDE_THE_WINDOW);
    const free = keyless(bundle, new Date(INSIDE_THE_WINDOW));

    // One nulled field is a hand edit and not a withheld view: the tell is all
    // five unconditional content strings at once, so a file short of that is
    // checked exactly as it always was and the edit is named.
    const edited = {
      ...(world.entry as unknown as Record<string, unknown>),
      claim: null,
    };

    const report = await verifyOffline(edited, free);
    expect(report.ok).toBe(false);
    expect(
      report.diffs.some((diff) => diff.reason === "entry_withheld"),
    ).toBe(false);
    expect(report.diffs.some((diff) => diff.check === "schema")).toBe(true);
  });

  it("checks a released export exactly as it always was", async () => {
    const { world, bundle } = await sealedWorld(AFTER_THE_WINDOW);
    const free = keyless(bundle, new Date(AFTER_THE_WINDOW));

    // Every window has run out, so the free view is the whole log and the
    // report says nothing was kept back.
    expect(hashLines(free)).toEqual([]);
    expect(free.events).toEqual(bundle.events);

    const report = await verifyOffline(world.entry, free);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.withheld).toBe(0);
  });
});

describe("the one script, inside the release window", () => {
  let directory: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "nomankind-verify-window-"));
  });

  afterAll(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("exits 0 and says how much the window kept back", async () => {
    const { world, bundle } = await sealedWorld(INSIDE_THE_WINDOW);
    const free = keyless(bundle, new Date(INSIDE_THE_WINDOW));
    const entryPath = join(directory, "entry.json");
    const bundlePath = join(directory, "log.json");
    await writeFile(entryPath, JSON.stringify(world.entry, null, 2), "utf8");
    await writeFile(bundlePath, JSON.stringify(free, null, 2), "utf8");

    const out: string[] = [];
    const err: string[] = [];
    const code = await verify(entryPath, bundlePath, {
      stdout: (line) => out.push(line),
      stderr: (line) => err.push(line),
    });

    expect(code).toBe(0);
    expect(err).toEqual([]);
    expect(out).toEqual([
      `schema ${SCHEMA_VERSION}`,
      `withheld ${hashLines(free).length}`,
      `ok ${world.entryId}`,
    ]);
    // The files really are the two files a stranger was handed.
    expect(JSON.parse(await readFile(bundlePath, "utf8"))).toBeTruthy();
  });

  it("prints the day a withheld entry's content opens, and exits 1", async () => {
    const { world, bundle } = await sealedWorld(INSIDE_THE_WINDOW);
    const free = keyless(bundle, new Date(INSIDE_THE_WINDOW));
    const held = await withholdEntry(world.entry, SIDECAR, "");
    const entryPath = join(directory, "withheld-entry.json");
    const bundlePath = join(directory, "withheld-log.json");
    await writeFile(entryPath, JSON.stringify(held.proof, null, 2), "utf8");
    await writeFile(bundlePath, JSON.stringify(free, null, 2), "utf8");

    const out: string[] = [];
    const err: string[] = [];
    const code = await verify(entryPath, bundlePath, {
      stdout: (line) => out.push(line),
      stderr: (line) => err.push(line),
    });

    // Nothing was verified, so the exit code is what it has always been for a
    // run that did not check out.
    expect(code).toBe(1);
    expect(err).toEqual([]);
    const opens = releaseDateOf(
      (world.entry as unknown as { seal: { sealed_at: string } }).seal
        .sealed_at,
    );
    expect(out).toEqual([
      `schema ${SCHEMA_VERSION}`,
      `withheld ${hashLines(free).length}`,
      `entry_withheld ${world.entryId}: content opens ${opens}`,
    ]);
  });

  it("says nothing about the window when nothing is withheld", async () => {
    const { world, bundle } = await sealedWorld(AFTER_THE_WINDOW);
    const entryPath = join(directory, "released-entry.json");
    const bundlePath = join(directory, "released-log.json");
    await writeFile(entryPath, JSON.stringify(world.entry, null, 2), "utf8");
    await writeFile(bundlePath, JSON.stringify(bundle, null, 2), "utf8");

    const out: string[] = [];
    const code = await verify(entryPath, bundlePath, {
      stdout: (line) => out.push(line),
      stderr: () => undefined,
    });

    expect(code).toBe(0);
    expect(out).toEqual([`schema ${SCHEMA_VERSION}`, `ok ${world.entryId}`]);
  });
});

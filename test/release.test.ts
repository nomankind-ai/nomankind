/**
 * The release window, as a rule (decisions D-100 and D-101).
 *
 * Whitepaper Section 8 as D-100 amends it: training on the data is free *on
 * release*, and the window is what the paid product is. The rule itself is four
 * functions and a clock somebody else supplies — an event's release date is its
 * covering seal's `sealed_at` plus the window, an entry's is its submission
 * event's, an unsealed event is not released, and what is withheld is content
 * and never proof.
 *
 * So what is pinned here is exactly that: the arithmetic at the boundary, on it
 * and a millisecond either side; null for a thing nothing has sealed; the
 * released head over a list of seals in any order; and the two shapes, over a
 * real entry derived from the offline verifier's own world rather than a
 * hand-written object — every hash, every signer, every seal and every derived
 * proof field still there, and the seven content fields and the approvers'
 * reasons null.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

import { deriveEntry } from "../src/index.js";
import type { Event } from "../src/events.js";
import { entryHash } from "../src/hash.js";
import { RELEASE_WINDOW_DAYS } from "../src/policy.js";
import {
  CONTENT_CORE_KEYS,
  isReleased,
  isWithheld,
  releaseDateOf,
  releasedHead,
  withholdEntry,
  withholdEvent,
} from "../src/release.js";
import type { Seal } from "../src/seal.js";
import {
  VERIFIED_ENTRY_ID,
  buildVerifyWorld,
  type VerifyWorld,
} from "./helpers/verify-world.js";

const DAY_MS = 86_400_000;

/** A seal as this file's arithmetic needs one: when it closed, and how far. */
function seal(sealedAt: string, lastSeq: number): Pick<Seal, "last_seq" | "sealed_at"> {
  return { sealed_at: sealedAt, last_seq: lastSeq };
}

describe("the release date", () => {
  it("is the seal's own instant plus the published window", () => {
    expect(releaseDateOf("2026-09-11T00:00:00.000Z")).toBe(
      new Date(
        Date.parse("2026-09-11T00:00:00.000Z") + RELEASE_WINDOW_DAYS * DAY_MS,
      ).toISOString(),
    );
    // The window is policy's one number and is read from there, never typed
    // beside the rule: thirty days, set by the maintainer (D-101).
    expect(RELEASE_WINDOW_DAYS).toBe(30);
  });

  it("keeps the time of day the seal closed at", () => {
    // A window in days from the instant, not to a midnight: an evening seal
    // opens in the evening, exactly as the disclosure window does.
    expect(releaseDateOf("2026-09-11T18:43:07.250Z")).toBe(
      "2026-10-11T18:43:07.250Z",
    );
  });

  it("refuses something that is not an instant", () => {
    expect(() => releaseDateOf("not a date")).toThrow(TypeError);
  });
});

describe("whether something is released", () => {
  const SEALED_AT = "2026-09-11T00:00:00.000Z";
  const OPENS = releaseDateOf(SEALED_AT);

  it("is released exactly at the window", () => {
    expect(isReleased(SEALED_AT, new Date(OPENS))).toBe(true);
  });

  it("is not released a millisecond before it", () => {
    expect(isReleased(SEALED_AT, new Date(Date.parse(OPENS) - 1))).toBe(false);
  });

  it("stays released afterwards", () => {
    expect(isReleased(SEALED_AT, new Date(Date.parse(OPENS) + DAY_MS))).toBe(
      true,
    );
  });

  it("is not released when nothing has sealed it", () => {
    // The window starts at the seal, so an event the log has not committed to
    // has no date to have reached — however old it is.
    expect(isReleased(null, new Date("2099-01-01T00:00:00.000Z"))).toBe(false);
  });
});

describe("the released head", () => {
  const EARLY = "2026-08-01T00:00:00.000Z";
  const LATE = "2026-09-01T00:00:00.000Z";

  it("is null while nothing has released", () => {
    expect(releasedHead([seal(LATE, 40)], new Date(LATE))).toBeNull();
    expect(releasedHead([], new Date("2099-01-01T00:00:00.000Z"))).toBeNull();
  });

  it("is the largest last_seq among the seals whose window has run out", () => {
    const seals = [seal(EARLY, 10), seal(EARLY, 25), seal(LATE, 40)];
    const between = new Date(Date.parse(releaseDateOf(EARLY)) + DAY_MS);
    expect(releasedHead(seals, between)).toBe(25);
    expect(releasedHead(seals, new Date(releaseDateOf(LATE)))).toBe(40);
  });

  it("does not depend on the order the seals were handed over in", () => {
    const seals = [seal(EARLY, 25), seal(LATE, 40), seal(EARLY, 10)];
    const between = new Date(Date.parse(releaseDateOf(EARLY)) + DAY_MS);
    expect(releasedHead(seals, between)).toBe(25);
  });
});

describe("a withheld event", () => {
  let world: VerifyWorld;
  let event: Event;

  beforeAll(async () => {
    world = await buildVerifyWorld();
    event = world.bundle.events[0]!;
  }, 60_000);

  it("keeps every field the proof is made of and drops the payload", () => {
    const line = withholdEvent(event);
    expect(line).toEqual({
      seq: event.seq,
      at: event.at,
      type: event.type,
      entry_id: event.entry_id,
      payload: null,
      prev_hash: event.prev_hash,
      hash: event.hash,
      withheld: true,
    });
    // The hash is the log's own and is never recomputed over the short line:
    // it is the leaf the seal's Merkle root is over.
    expect(line.hash).toBe(event.hash);
    expect(isWithheld(line)).toBe(true);
    expect(isWithheld(event)).toBe(false);
  });

  it("is the same line when it is withheld again", () => {
    // What lets an export built from an already-withheld read be byte-identical
    // to one built from the whole log.
    const once = withholdEvent(event);
    expect(withholdEvent(once as unknown as Event)).toEqual(once);
  });
});

describe("a withheld entry", () => {
  let world: VerifyWorld;
  let derived: ReturnType<typeof deriveEntry>;
  const RELEASE_DATE = "2026-10-11T00:00:00.000Z";

  beforeAll(async () => {
    world = await buildVerifyWorld();
    derived = deriveEntry([...world.bundle.events], VERIFIED_ENTRY_ID, {
      now: world.bundle.as_of,
    });
  }, 60_000);

  it("nulls the seven content fields and nothing else of the core", async () => {
    const { proof } = await withholdEntry(
      derived.entry,
      derived.sidecar,
      RELEASE_DATE,
    );
    const entry = derived.entry as Record<string, unknown>;
    for (const key of CONTENT_CORE_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(entry, key)) continue;
      expect([key, (proof as Record<string, unknown>)[key]]).toEqual([key, null]);
    }
    expect(CONTENT_CORE_KEYS).toEqual([
      "claim",
      "before",
      "after",
      "effective_at",
      "citation",
      "evidence",
      "observation",
    ]);
    // The claim was really there to begin with: a test that nulled nothing
    // would pass the loop above.
    expect(entry["claim"]).not.toBeNull();
  });

  it("keeps every proof field, hash, signer and seal exactly as it was", async () => {
    const { proof } = await withholdEntry(
      derived.entry,
      derived.sidecar,
      RELEASE_DATE,
    );
    const entry = derived.entry as Record<string, unknown>;
    const held = proof as Record<string, unknown>;
    for (const key of [
      "id",
      "subject",
      "category",
      "domain",
      "evidence_tier",
      "snapshot_hash",
      "norm_version",
      "supersedes",
      "author",
      "author_operator",
      "submitted_at",
      "signature",
      "seal",
      "status",
      "verified_at",
      "expires_at",
      "stale",
      "superseded_by",
      "overturned_by",
      "staleness_window_days",
    ]) {
      expect([key, held[key]]).toEqual([key, entry[key]]);
    }
    // The same keys, in the same order: a withheld entry is the entry, short of
    // its content, and never a different document.
    expect(Object.keys(held)).toEqual(Object.keys(entry));
  });

  it("withholds an approver's reason and keeps the rest of the record", async () => {
    const { proof } = await withholdEntry(
      derived.entry,
      derived.sidecar,
      RELEASE_DATE,
    );
    const approvers = (derived.entry as Record<string, unknown>)[
      "approvers"
    ] as Record<string, unknown>[];
    const held = (proof as Record<string, unknown>)["approvers"] as Record<
      string,
      unknown
    >[];
    expect(held).toHaveLength(approvers.length);
    expect(approvers.length).toBeGreaterThan(0);
    for (let index = 0; index < approvers.length; index += 1) {
      const one = approvers[index]!;
      const line = held[index]!;
      if (Object.prototype.hasOwnProperty.call(one, "reason")) {
        expect(line["reason"]).toBeNull();
      }
      expect(line["agent"]).toBe(one["agent"]);
      expect(line["operator"]).toBe(one["operator"]);
      expect(line["decision"]).toBe(one["decision"]);
      expect(line["signed_at"]).toBe(one["signed_at"]);
      expect(line["snapshot_hash"]).toBe(one["snapshot_hash"]);
    }
  });

  it("carries the release date beside the entry and never inside it", async () => {
    const withheld = await withholdEntry(
      derived.entry,
      derived.sidecar,
      RELEASE_DATE,
    );
    expect(withheld.release_date).toBe(RELEASE_DATE);
    expect(
      Object.prototype.hasOwnProperty.call(withheld.proof, "release_date"),
    ).toBe(false);
    // The sidecar is untouched: every key of it is derived from proof.
    expect(withheld.sidecar).toBe(derived.sidecar);
  });

  it("leaves the entry it was given alone", async () => {
    const before = JSON.stringify(derived.entry);
    await withholdEntry(derived.entry, derived.sidecar, RELEASE_DATE);
    expect(JSON.stringify(derived.entry)).toBe(before);
  });

  // The hash is the whole reason a withheld entry is called proof at all: a
  // reader who is handed a nulled core and no hash has been handed a record
  // they cannot name. It is taken over the entry before anything is nulled, so
  // it is the hash of the released entry to the byte -- and a hash taken over
  // the nulled proof is a different number, which is what the second half of
  // this pins.
  it("carries the released entry's own hash, over the whole core", async () => {
    const withheld = await withholdEntry(
      derived.entry,
      derived.sidecar,
      RELEASE_DATE,
    );
    expect(withheld.entry_hash).toBe(await entryHash(derived.entry));
    expect(withheld.entry_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(await entryHash(withheld.proof)).not.toBe(withheld.entry_hash);
  });
});

/**
 * The paper's four amendments (decision D-100).
 *
 * A page can be made to say anything a test asks for; the paper is the document
 * the pages are checked against. So each amendment is pinned where it belongs —
 * labeled, and beside the sentence it makes precise rather than appended
 * somewhere a reader of that sentence would never reach it.
 */
const whitepaper = readFileSync(
  fileURLToPath(new URL("../paper/WHITEPAPER.md", import.meta.url)),
  "utf8",
);

describe("the paper carries the release window (D-100)", () => {
  const LABEL = "[Spec change 2026-09-11, D-100]";

  it("amends exactly four sentences, and labels every one of them", () => {
    expect(whitepaper.split(LABEL)).toHaveLength(5);
  });

  it("makes the training path free on release (Section 8)", () => {
    const promise = whitepaper.indexOf(
      "Training on the data itself is free by license.",
    );
    const amendment = whitepaper.indexOf(`${LABEL} Free on release`);
    expect(promise).toBeGreaterThan(-1);
    expect(amendment).toBeGreaterThan(promise);
    expect(whitepaper).toContain("RELEASE_WINDOW_DAYS in the policy module");
    expect(whitepaper).toContain(
      "thirty days after the seal that covers its submission",
    );
  });

  it("makes the free tier free once released, forever (the money section)", () => {
    const promise = whitepaper.indexOf(
      "The log is free to read at low volume, forever.",
    );
    const amendment = whitepaper.indexOf(`${LABEL} Once released, forever`);
    expect(promise).toBeGreaterThan(-1);
    expect(amendment).toBeGreaterThan(promise);
    expect(whitepaper).toContain(
      "the thirty-day window before release is part of the paid product",
    );
  });

  it("says what the mirror publishes daily (Section 11)", () => {
    const mirror = whitepaper.indexOf(
      "The daily log mirror lives in its own public repository",
    );
    const amendment = whitepaper.indexOf(`${LABEL} What it publishes daily`);
    expect(mirror).toBeGreaterThan(-1);
    expect(amendment).toBeGreaterThan(mirror);
    expect(whitepaper).toContain(
      "exported as a hash line — the same event, its payload withheld",
    );
  });

  it("says what a fork leaves with (the conclusion)", () => {
    const exit = whitepaper.indexOf(
      "the remedy is a fork that leaves with the entire record.",
    );
    const amendment = whitepaper.indexOf(
      `${LABEL} With the entire record older than the release window`,
    );
    expect(exit).toBeGreaterThan(-1);
    expect(amendment).toBeGreaterThan(exit);
    expect(whitepaper).toContain("and the proof of the rest");
    // The conclusion is the last of the four: a paragraph that landed in the
    // wrong section would still carry the words.
    expect(amendment).toBeGreaterThan(
      whitepaper.indexOf(`${LABEL} What it publishes daily`),
    );
  });
});

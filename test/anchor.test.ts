import { describe, expect, it } from "vitest";

import {
  ANCHOR_REFUSALS,
  anchorHash,
  buildAnchor,
  utcDay,
  verifyAnchor,
  type Anchor,
  type SealLike,
} from "../src/anchor.js";

const root = (seq: number): string => `sha256:${String(seq).padStart(64, "0")}`;

const seal = (seq: number, sealedAt: string): SealLike => ({
  seq,
  root: root(seq),
  sealed_at: sealedAt,
});

/**
 * Two UTC days of seals. Seal 3 is written with a +05:30 offset on a local
 * calendar day of the 8th, but lands at 23:00Z on the 7th, so it anchors to
 * the 7th; seal 4 closes the 7th at 23:59:59Z and seal 5 opens the 8th.
 */
const SEALS: readonly SealLike[] = [
  seal(1, "2026-09-07T00:00:00Z"),
  seal(2, "2026-09-07T12:00:00Z"),
  seal(3, "2026-09-08T04:30:00+05:30"),
  seal(4, "2026-09-07T23:59:59Z"),
  seal(5, "2026-09-08T00:00:00Z"),
  seal(6, "2026-09-08T09:00:00Z"),
];

async function anchorFor(
  date: string,
  seals: readonly SealLike[] = SEALS,
): Promise<Anchor> {
  const result = await buildAnchor(seals, date);
  if (!result.ok) {
    throw new Error(`expected an anchor for ${date}, got ${result.reason}`);
  }
  return result.anchor;
}

describe("utcDay", () => {
  it("takes the UTC day, not the local one", () => {
    expect(utcDay("2026-09-07T00:00:00Z")).toBe("2026-09-07");
    expect(utcDay("2026-09-07T23:59:59Z")).toBe("2026-09-07");
    expect(utcDay("2026-09-08T00:00:00Z")).toBe("2026-09-08");
    // Local date the 8th, UTC date the 7th.
    expect(utcDay("2026-09-08T04:30:00+05:30")).toBe("2026-09-07");
  });

  it("throws RangeError on an unparsable date-time", () => {
    expect(() => utcDay("yesterday")).toThrow(RangeError);
    expect(() => utcDay("")).toThrow(RangeError);
    expect(() => utcDay("2026-99-99T00:00:00Z")).toThrow(RangeError);
  });

  it("does not police out-of-range days the engine rolls over", () => {
    // The engine parses this and rolls it to March 2. utcDay reports the day it
    // parsed to; refusing an impossible calendar day is buildAnchor's bad_date.
    expect(utcDay("2026-02-30T00:00:00Z")).toBe("2026-03-02");
  });
});

describe("ANCHOR_REFUSALS", () => {
  it("names both refusals", () => {
    expect(ANCHOR_REFUSALS).toEqual(["no_seals", "bad_date"]);
  });
});

describe("buildAnchor", () => {
  it("splits seals by UTC day", async () => {
    expect((await anchorFor("2026-09-07")).roots).toEqual([
      root(1),
      root(2),
      root(3),
      root(4),
    ]);
    expect((await anchorFor("2026-09-08")).roots).toEqual([root(5), root(6)]);
  });

  it("carries the day's roots in seq order with the right bounds", async () => {
    const anchor = await anchorFor("2026-09-07");
    expect(anchor).toEqual({
      date: "2026-09-07",
      first_seal_seq: 1,
      last_seal_seq: 4,
      roots: [root(1), root(2), root(3), root(4)],
      hash: await anchorHash("2026-09-07", [root(1), root(2), root(3), root(4)]),
      external: null,
    });
  });

  it("orders by seq however the seals arrive", async () => {
    const shuffled = [SEALS[3]!, SEALS[0]!, SEALS[2]!, SEALS[1]!];
    expect((await anchorFor("2026-09-07", shuffled)).roots).toEqual([
      root(1),
      root(2),
      root(3),
      root(4),
    ]);
  });

  it("leaves the external receipt null", async () => {
    expect((await anchorFor("2026-09-08")).external).toBeNull();
  });

  it("leaves the anchor hash alone when the receipt arrives", async () => {
    // D-037, item 5: the hash covers the date and the roots and nothing else,
    // so posting the hash and getting a receipt back cannot change the thing
    // that was posted.
    const anchor = await anchorFor("2026-09-08");
    const timestamped: Anchor = {
      ...anchor,
      external: {
        kind: "opentimestamps",
        calendar: "https://alice.btc.calendar.opentimestamps.org",
        submitted_at: "2026-09-08T23:59:00Z",
        proof: "AE9wZW5UaW1lc3RhbXBz",
        upgraded: null,
      },
    };
    expect(timestamped.hash).toBe(await anchorHash("2026-09-08", anchor.roots));
    expect(await verifyAnchor(timestamped, SEALS)).toBe(true);
    // And a receipt cannot make a false anchor true: the roots still decide.
    expect(await verifyAnchor({ ...timestamped, roots: [root(5)] }, SEALS)).toBe(
      false,
    );
  });

  it("refuses a day with no seals rather than anchoring nothing", async () => {
    expect(await buildAnchor(SEALS, "2026-09-09")).toEqual({
      ok: false,
      reason: "no_seals",
    });
    expect(await buildAnchor([], "2026-09-07")).toEqual({
      ok: false,
      reason: "no_seals",
    });
  });

  it("refuses a date that is not a real calendar day in YYYY-MM-DD", async () => {
    for (const date of ["2026-02-30", "2026-9-7", "2026-13-01", "", "2026-09-07T00:00:00Z"]) {
      expect(await buildAnchor(SEALS, date)).toEqual({
        ok: false,
        reason: "bad_date",
      });
    }
  });
});

describe("anchorHash", () => {
  it("is stable across calls for the same date and roots", async () => {
    const first = await anchorHash("2026-09-08", [root(5), root(6)]);
    const second = await anchorHash("2026-09-08", [root(5), root(6)]);
    expect(first).toBe(second);
  });

  it("matches its known answer", async () => {
    const anchor = await anchorFor("2026-09-08");
    expect(anchor.hash).toBe(
      "sha256:f1b74ab0f50fde9eaa8e911a4c7d66ee80cba23c32ab0885af04275bb0121998",
    );
  });
});

describe("verifyAnchor", () => {
  it("holds for an honest anchor", async () => {
    expect(await verifyAnchor(await anchorFor("2026-09-07"), SEALS)).toBe(true);
    expect(await verifyAnchor(await anchorFor("2026-09-08"), SEALS)).toBe(true);
  });

  it("fails when one root is altered", async () => {
    const anchor = await anchorFor("2026-09-07");
    const roots = [...anchor.roots];
    roots[2] = root(99);
    expect(
      await verifyAnchor(
        { ...anchor, roots, hash: await anchorHash(anchor.date, roots) },
        SEALS,
      ),
    ).toBe(false);
  });

  it("fails when the roots are reordered", async () => {
    const anchor = await anchorFor("2026-09-07");
    const roots = [anchor.roots[1]!, anchor.roots[0]!, ...anchor.roots.slice(2)];
    expect(
      await verifyAnchor(
        { ...anchor, roots, hash: await anchorHash(anchor.date, roots) },
        SEALS,
      ),
    ).toBe(false);
  });

  it("fails when a seal is added to the day after anchoring", async () => {
    const anchor = await anchorFor("2026-09-07");
    const later = [...SEALS, seal(7, "2026-09-07T23:59:00Z")];
    expect(await verifyAnchor(anchor, later)).toBe(false);
  });

  it("fails when the hash is tampered with", async () => {
    const anchor = await anchorFor("2026-09-07");
    expect(
      await verifyAnchor({ ...anchor, hash: `sha256:${"0".repeat(64)}` }, SEALS),
    ).toBe(false);
  });

  it("fails when the seq bounds do not match the day", async () => {
    const anchor = await anchorFor("2026-09-07");
    expect(await verifyAnchor({ ...anchor, first_seal_seq: 0 }, SEALS)).toBe(false);
    expect(await verifyAnchor({ ...anchor, last_seal_seq: 9 }, SEALS)).toBe(false);
  });

  it("returns false rather than throwing on a malformed anchor or seal", async () => {
    const anchor = await anchorFor("2026-09-07");
    expect(await verifyAnchor({ ...anchor, date: "2026-9-7" }, SEALS)).toBe(false);
    expect(await verifyAnchor(anchor, [seal(1, "yesterday")])).toBe(false);
  });
});

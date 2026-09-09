/**
 * The reconfirmation bounty.
 *
 * Whitepaper Section 7, "Freshness and decay": stale entries earn half rate and
 * the withheld half "builds up on the entry as a reconfirmation bounty, paid to
 * whoever makes it fresh again". So the question each of these asks is the one
 * the money turns on: did this reconfirmation arrive on an entry that had gone
 * stale, and if so, over exactly what window.
 */

import { describe, expect, it } from "vitest";
import {
  appendEvent,
  bountyAccrual,
  type Event,
  type ReconfirmationRecord,
} from "../src/index.js";

const OPERATOR = "lattice.example";
const AGENT = "1F916:6PmY_Rl-vJoqcBTdMBoMbLZLc0nUqYHpXK0dK7hM8kQ";
const ENTRY_ID = "nmk_01K4Q8ZQ2M3N4P5R6S7T8V9W0X";
const AT = "2026-09-08T12:00:00.000Z";

function record(): ReconfirmationRecord {
  return {
    agent: AGENT,
    operator: OPERATOR,
    snapshot_hash: `sha256:${"4d".repeat(32)}`,
    reproduction: null,
    observation: null,
    signed_at: AT,
  };
}

/** A real sealed reconfirmation, so seq and at are the log's own, not invented. */
async function reconfirmation(): Promise<Event<"reconfirmation">> {
  const log = await appendEvent([], {
    at: AT,
    type: "reconfirmation",
    entry_id: ENTRY_ID,
    payload: { record: record(), signature: "c2lnbmF0dXJl" },
  });
  return log[0] as Event<"reconfirmation">;
}

describe("bountyAccrual", () => {
  it("accrues nothing on an entry that was still fresh", async () => {
    // Section 6 lets any trusted operator reconfirm a verified entry, inside its
    // window or past it. Inside the window nothing was withheld, so there is
    // nothing to pay.
    expect(
      bountyAccrual({ expires_at: "2026-12-01", stale: false }, await reconfirmation()),
    ).toBeNull();
  });

  it("accrues nothing on an entry with no window at all", async () => {
    // An event-category entry carries no expires_at and can never go stale, so
    // it can never build a bounty — even if something set the flag.
    expect(
      bountyAccrual({ expires_at: null, stale: false }, await reconfirmation()),
    ).toBeNull();
    expect(
      bountyAccrual({ expires_at: null, stale: true }, await reconfirmation()),
    ).toBeNull();
  });

  it("records the whole stale window when the entry had gone stale", async () => {
    const event = await reconfirmation();
    const accrual = bountyAccrual(
      { expires_at: "2026-06-01", stale: true },
      event,
    );

    expect(accrual).toEqual({
      kind: "bounty_accrual",
      entry_id: ENTRY_ID,
      operator: OPERATOR,
      // The last day the entry was fresh, and the instant it became fresh again.
      stale_from: "2026-06-01",
      stale_until: AT,
      seq: event.seq,
      // Section 9's pricing is M21's; nothing here invents a number.
      amount_cents: null,
    });
  });

  it("reads the operator off the record and the position off the event", async () => {
    const log = await appendEvent([], {
      at: "2026-01-01T00:00:00.000Z",
      type: "operator_registered",
      entry_id: null,
      payload: { operator: "harrier.example", maintainer: false },
    });
    const later = await appendEvent(log, {
      at: "2027-01-02T03:04:05.000Z",
      type: "reconfirmation",
      entry_id: ENTRY_ID,
      payload: {
        record: { ...record(), operator: "harrier.example" },
        signature: "c2lnbmF0dXJl",
      },
    });
    const event = later[later.length - 1] as Event<"reconfirmation">;

    expect(bountyAccrual({ expires_at: "2026-06-01", stale: true }, event)).toEqual({
      kind: "bounty_accrual",
      entry_id: ENTRY_ID,
      operator: "harrier.example",
      stale_from: "2026-06-01",
      stale_until: "2027-01-02T03:04:05.000Z",
      seq: 1,
      amount_cents: null,
    });
  });

  it("refuses a reconfirmation carrying no entry_id", async () => {
    const event = { ...(await reconfirmation()), entry_id: null };
    expect(() =>
      bountyAccrual({ expires_at: "2026-06-01", stale: true }, event),
    ).toThrow(TypeError);
  });
});

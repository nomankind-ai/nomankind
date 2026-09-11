/**
 * The change-alert kernel: what one sealed event alerts, who hears it, and the
 * signature a subscriber checks.
 *
 * Whitepaper Section 9, Money: "Revenue comes from high-rate API access,
 * structured feeds and webhooks, change alerts." Everything in src/alerts.ts is
 * pure except the one HMAC, so all of it is checked here without a database, a
 * clock or a network: the six kinds are derived from an event and two derived
 * entries, the filter is exact-match, and the signature is recomputed from the
 * published recipe rather than compared against a golden string nobody could
 * rebuild.
 *
 * The end-to-end behaviour — the doors, the deliveries, the retries — is in
 * test/m24-alerts-end-to-end.test.ts, against the real router and real D1.
 */

import { describe, expect, it } from "vitest";

import {
  HASH_TAG_ALERT,
  alertMatches,
  alertSignatureHeader,
  alertSigningBytes,
  alertsFromEvent,
  isAlertUrl,
  signAlert,
  type AlertFilter,
} from "../src/alerts.js";
import type { Event } from "../src/events.js";
import { ALERT_KINDS, type AlertKind } from "../src/policy.js";
import type { Entry } from "../src/schema.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** One event of a type, at a position. The payload is never read by the kernel. */
function event(type: Event["type"], seq: number, entryId: string): Event {
  return {
    seq,
    at: "2026-09-11T12:00:00.000Z",
    type,
    entry_id: entryId,
    payload: {} as Event["payload"],
    prev_hash: null,
    hash: "sha256:" + "0".repeat(64),
  };
}

/** An entry as derivation leaves one, in the fields an alert reads. */
function entry(overrides: Record<string, unknown> = {}): Entry {
  return {
    id: "nmk_target",
    domain: "ai-ecosystem",
    subject: "merlin/merlin-4",
    category: "pricing",
    supersedes: null,
    status: "draft",
    ...overrides,
  } as Entry;
}

const ANY: AlertFilter = {
  domain: null,
  subject: null,
  category: null,
  kinds: null,
};

// ---------------------------------------------------------------------------
// The filter
// ---------------------------------------------------------------------------

describe("alertMatches", () => {
  const alert = {
    domain: "ai-ecosystem",
    subject: "merlin/merlin-4",
    category: "pricing",
    kind: "verified" as AlertKind,
  };

  it("passes everything when the endpoint named no filter", () => {
    expect(alertMatches(ANY, alert)).toBe(true);
  });

  it("passes each field that matches and refuses each that does not", () => {
    for (const [field, value] of [
      ["domain", "ai-ecosystem"],
      ["subject", "merlin/merlin-4"],
      ["category", "pricing"],
    ] as const) {
      expect(alertMatches({ ...ANY, [field]: value }, alert)).toBe(true);
      expect(alertMatches({ ...ANY, [field]: "something-else" }, alert)).toBe(
        false,
      );
    }
  });

  it("matches a subject exactly and never by prefix", () => {
    // A prefix match would subscribe an endpoint to subjects that did not exist
    // when it was registered, which is not what the holder asked for.
    expect(alertMatches({ ...ANY, subject: "merlin" }, alert)).toBe(false);
    expect(alertMatches({ ...ANY, subject: "merlin/merlin-40" }, alert)).toBe(
      false,
    );
  });

  it("passes a kind the list names and refuses one it leaves out", () => {
    expect(alertMatches({ ...ANY, kinds: ["verified"] }, alert)).toBe(true);
    expect(
      alertMatches({ ...ANY, kinds: ["submitted", "rejected"] }, alert),
    ).toBe(false);
  });

  it("needs every named field at once", () => {
    expect(
      alertMatches(
        {
          domain: "ai-ecosystem",
          subject: "merlin/merlin-4",
          category: "limit",
          kinds: ["verified"],
        },
        alert,
      ),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The six kinds
// ---------------------------------------------------------------------------

describe("alertsFromEvent", () => {
  it("alerts submitted for a submission", () => {
    const after = entry({ id: "nmk_new" });
    expect(
      alertsFromEvent(event("entry_submitted", 3, "nmk_new"), {
        before: null,
        after,
      }),
    ).toEqual([{ kind: "submitted", entry: after }]);
  });

  it("alerts verified when a validation moves the entry to verified", () => {
    const after = entry({ status: "verified" });
    expect(
      alertsFromEvent(event("validation", 9, "nmk_target"), {
        before: entry({ status: "draft" }),
        after,
      }),
    ).toEqual([{ kind: "verified", entry: after }]);
  });

  it("alerts rejected when a validation rejects", () => {
    const after = entry({ status: "rejected" });
    expect(
      alertsFromEvent(event("validation", 9, "nmk_target"), {
        before: entry({ status: "draft" }),
        after,
      }),
    ).toEqual([{ kind: "rejected", entry: after }]);
  });

  it("alerts nothing for a validation that left the entry a draft", () => {
    // The first of two approvals decides nothing: the status is what moved or
    // did not, and a change alert about no change is noise.
    expect(
      alertsFromEvent(event("validation", 8, "nmk_target"), {
        before: entry({ status: "draft" }),
        after: entry({ status: "draft" }),
      }),
    ).toEqual([]);
  });

  it("alerts the target superseded when the verifying entry names it", () => {
    const after = entry({
      id: "nmk_new",
      status: "verified",
      supersedes: "nmk_target",
    });
    const target = entry({ id: "nmk_target", status: "superseded" });
    expect(
      alertsFromEvent(event("validation", 12, "nmk_new"), {
        before: entry({ id: "nmk_new", supersedes: "nmk_target" }),
        after,
        target,
      }),
    ).toEqual([
      { kind: "verified", entry: after },
      { kind: "superseded", entry: target },
    ]);
  });

  it("does not alert superseded while the target has not moved", () => {
    const after = entry({
      id: "nmk_new",
      status: "verified",
      supersedes: "nmk_target",
    });
    const target = entry({ id: "nmk_target", status: "verified" });
    expect(
      alertsFromEvent(event("validation", 12, "nmk_new"), {
        before: entry({ id: "nmk_new", supersedes: "nmk_target" }),
        after,
        target,
      }),
    ).toEqual([{ kind: "verified", entry: after }]);
  });

  it("alerts reconfirmed for a reconfirmation, status unchanged", () => {
    const after = entry({ status: "verified" });
    expect(
      alertsFromEvent(event("reconfirmation", 20, "nmk_target"), {
        before: entry({ status: "verified" }),
        after,
      }),
    ).toEqual([{ kind: "reconfirmed", entry: after }]);
  });

  it("alerts overturned for an upheld dispute, on the disputed entry", () => {
    // The event is scoped to the target (src/events.ts), so the entry derived
    // at its position is the one the subscriber was following.
    const after = entry({ status: "overturned" });
    expect(
      alertsFromEvent(event("dispute_upheld", 30, "nmk_target"), {
        before: entry({ status: "verified" }),
        after,
      }),
    ).toEqual([{ kind: "overturned", entry: after }]);
  });

  it("alerts nothing for the log's own bookkeeping", () => {
    for (const type of [
      "operator_registered",
      "pool_snapshot",
      "assignment",
      "read_count",
      "dispute_filed",
      "attestation_scored",
    ] as const) {
      expect(
        alertsFromEvent(event(type, 40, "nmk_target"), {
          before: entry(),
          after: entry(),
        }),
        `${type} alerted something`,
      ).toEqual([]);
    }
  });

  it("only ever names a kind the policy publishes", () => {
    const produced = [
      ...alertsFromEvent(event("entry_submitted", 1, "a"), {
        before: null,
        after: entry(),
      }),
      ...alertsFromEvent(event("validation", 2, "a"), {
        before: entry(),
        after: entry({ status: "verified" }),
      }),
      ...alertsFromEvent(event("validation", 3, "a"), {
        before: entry(),
        after: entry({ status: "rejected" }),
      }),
      ...alertsFromEvent(event("reconfirmation", 4, "a"), {
        before: entry(),
        after: entry({ status: "verified" }),
      }),
      ...alertsFromEvent(event("dispute_upheld", 5, "a"), {
        before: entry(),
        after: entry({ status: "overturned" }),
      }),
    ];
    for (const alert of produced) {
      expect(ALERT_KINDS).toContain(alert.kind);
    }
  });
});

// ---------------------------------------------------------------------------
// The signature
// ---------------------------------------------------------------------------

describe("the delivery signature", () => {
  const SECRET = "PDKn7l3vQ0Yy0rV0Yx8mYx1gk8b9xY4xJ1o0aKQ2lQk";
  const BODY = '{"id":"alert_0001","kind":"verified"}';

  it("names its own construction", () => {
    expect(HASH_TAG_ALERT).toBe("nomankind-alert-v1");
  });

  it("covers the timestamp, a dot, and the body exactly as sent", () => {
    const bytes = alertSigningBytes(1_757_592_000, BODY);
    expect(new TextDecoder().decode(bytes)).toBe(`1757592000.${BODY}`);
  });

  it("is the HMAC-SHA256 of those bytes, in the provider's own header shape", async () => {
    const timestamp = 1_757_592_000;
    const hex = await signAlert(SECRET, timestamp, BODY);
    expect(hex).toMatch(/^[0-9a-f]{64}$/);
    expect(alertSignatureHeader(timestamp, hex)).toBe(`t=${timestamp},v1=${hex}`);

    // Recomputed from the published recipe by a subscriber that holds only the
    // secret: this is the whole check a reader is asked to make.
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET) as unknown as BufferSource,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const signature = Uint8Array.from(
      (hex.match(/../g) ?? []).map((pair) => Number.parseInt(pair, 16)),
    );
    expect(
      await globalThis.crypto.subtle.verify(
        "HMAC",
        key,
        signature as unknown as BufferSource,
        alertSigningBytes(timestamp, BODY) as unknown as BufferSource,
      ),
    ).toBe(true);
  });

  it("changes with the timestamp, so a capture cannot be replayed later", async () => {
    const first = await signAlert(SECRET, 1_757_592_000, BODY);
    const second = await signAlert(SECRET, 1_757_592_001, BODY);
    expect(second).not.toBe(first);
  });

  it("changes with one byte of the body", async () => {
    const first = await signAlert(SECRET, 1_757_592_000, BODY);
    const second = await signAlert(SECRET, 1_757_592_000, `${BODY} `);
    expect(second).not.toBe(first);
  });

  it("changes with the secret", async () => {
    const first = await signAlert(SECRET, 1_757_592_000, BODY);
    const second = await signAlert(`${SECRET}x`, 1_757_592_000, BODY);
    expect(second).not.toBe(first);
  });
});

// ---------------------------------------------------------------------------
// Where an alert may be posted
// ---------------------------------------------------------------------------

describe("isAlertUrl", () => {
  it("takes an https URL with a dotted hostname", () => {
    for (const url of [
      "https://hooks.example.com/nomankind",
      "https://example.com",
      "https://deep.sub.example.co.uk/a/b?c=d",
      "https://example.com:8443/hook",
    ]) {
      expect(isAlertUrl(url), url).toBe(true);
    }
  });

  it("refuses anything but https", () => {
    for (const url of [
      "http://hooks.example.com/nomankind",
      "ftp://hooks.example.com/",
      "javascript:fetch('x')",
      "//hooks.example.com/",
      "/hooks",
    ]) {
      expect(isAlertUrl(url), url).toBe(false);
    }
  });

  it("refuses a local address, whatever it is spelled as", () => {
    for (const url of [
      "https://localhost/hook",
      "https://localhost:8787/hook",
      "https://hooks.localhost/hook",
      "https://intranet/hook",
    ]) {
      expect(isAlertUrl(url), url).toBe(false);
    }
  });

  it("refuses credentials in the URL", () => {
    expect(isAlertUrl("https://user:pass@hooks.example.com/")).toBe(false);
    expect(isAlertUrl("https://user@hooks.example.com/")).toBe(false);
  });

  it("never throws on a value that is not a URL at all", () => {
    for (const value of [null, undefined, 7, {}, [], "", "not a url"]) {
      expect(isAlertUrl(value)).toBe(false);
    }
  });
});

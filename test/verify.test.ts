/**
 * The offline verifier (src/verify.ts): the paper's two files and one script.
 *
 * Goals and non-goals, goal 4: "anyone can check the proof offline with two
 * files and one script". The two files are an entry and the log bundle beside
 * it, and every test here is the same story: build a real world, hand the
 * verifier both files, and then edit exactly one thing and watch it named.
 *
 * Every fixture carries every derived field explicitly, seal null included: the
 * entries come out of deriveEntry, so nothing is written by hand and nothing is
 * absent because it happened to be empty.
 */

import { describe, expect, it } from "vitest";

import { appendEvent, type ApproverRecord, type Event } from "../src/index.js";
import { SCHEMA_VERSION } from "../src/policy.js";
import { CHECKS, verifyOffline, type Diff, type VerifyReport } from "../src/verify.js";
import { signRecord } from "../src/records.js";
import {
  PROVIDER_OPERATOR,
  buildVerifyWorld,
  type VerifyWorld,
} from "./helpers/verify-world.js";

type Json = Record<string, unknown>;

const SNAKE_CASE = /^[a-z][a-z0-9]*(_[a-z0-9]+)*$/;

/** Every diff, whatever else a test asserts, has to be readable by a stranger. */
function expectWellFormed(report: VerifyReport): void {
  expect(report.ok).toBe(report.diffs.length === 0);
  for (const diff of report.diffs) {
    expect(CHECKS).toContain(diff.check);
    expect(diff.field.startsWith("/")).toBe(true);
    expect(diff.field.length).toBeGreaterThan(0);
    expect(diff.reason).toMatch(SNAKE_CASE);
    // Small and JSON-serializable: never a whole object.
    expect(JSON.stringify(diff.expected ?? null).length).toBeLessThan(200);
    expect(JSON.stringify(diff.actual ?? null).length).toBeLessThan(200);
  }
}

function find(report: VerifyReport, check: string, field: string): Diff[] {
  return report.diffs.filter(
    (diff) => diff.check === check && diff.field === field,
  );
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

/** One world per test file run: the tests copy it and edit their copy. */
let cached: VerifyWorld | null = null;

async function world(): Promise<VerifyWorld> {
  if (cached === null) cached = await buildVerifyWorld();
  return cached;
}

/** The entry and the bundle, deep-copied so a test's edits stay its own. */
async function files(): Promise<{ entry: Json; bundle: Json; source: VerifyWorld }> {
  const source = await world();
  return {
    entry: clone(source.entry) as Json,
    bundle: clone(source.bundle) as unknown as Json,
    source,
  };
}

describe("verifyOffline: the clean world", () => {
  it("verifies the sealed, verified entry with no diffs", async () => {
    const { entry, bundle } = await files();
    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.entry_id).toBe(entry["id"]);
    expect(entry["status"]).toBe("verified");
  });

  it("verifies the unsealed draft, which carries seal null explicitly", async () => {
    const source = await world();
    const draft = clone(source.draftEntry) as Json;
    expect(Object.prototype.hasOwnProperty.call(draft, "seal")).toBe(true);
    expect(draft["seal"]).toBeNull();
    expect(draft["status"]).toBe("draft");

    const report = await verifyOffline(draft, clone(source.bundle));
    expectWellFormed(report);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
  });
});

describe("verifyOffline: one edited field at a time", () => {
  it("names a hand-edited status", async () => {
    const { entry, bundle } = await files();
    entry["status"] = "draft";

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    const diffs = find(report, "derived", "/status");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("mismatch");
    expect(diffs[0]!.expected).toBe("verified");
    expect(diffs[0]!.actual).toBe("draft");
  });

  it("names an edited claim on both the signature and the core", async () => {
    const { entry, bundle } = await files();
    entry["claim"] = "gpt-5 input price is $1.00 per million tokens";

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    expect(find(report, "signature", "/signature")).toHaveLength(1);
    expect(find(report, "signature", "/signature")[0]!.reason).toBe(
      "bad_signature",
    );
    const core = find(report, "core", "/claim");
    expect(core).toHaveLength(1);
    expect(core[0]!.reason).toBe("mismatch");
  });

  it("names a dropped approver on the recompute", async () => {
    const { entry, bundle } = await files();
    const approvers = entry["approvers"] as unknown[];
    expect(approvers.length).toBeGreaterThan(1);
    entry["approvers"] = approvers.slice(1);

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "derived", "/approvers");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("mismatch");
    expect(diffs[0]!.expected).toBe(approvers.length);
    expect(diffs[0]!.actual).toBe(approvers.length - 1);
  });

  it("names a broken chain when an earlier event's payload is edited", async () => {
    const { entry, bundle } = await files();
    const events = bundle["events"] as Json[];
    const target = events.find((event) => event["type"] === "operator_trusted")!;
    (target["payload"] as Json)["operator"] = "op_impostor";

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const chain = report.diffs.filter((diff) => diff.check === "chain");
    expect(chain).toHaveLength(1);
    expect(chain[0]!.reason).toBe("bad_hash");
    expect(chain[0]!.field).toBe(`/events/${target["seq"] as number}`);
  });

  it("names an edited archived capture", async () => {
    const { entry, bundle, source } = await files();
    const edited = new TextDecoder()
      .decode(source.captureBytes)
      .replace("$2.50", "$2.60");
    const captures = bundle["captures"] as Record<string, Json>;
    const hash = entry["snapshot_hash"] as string;
    captures[hash]!["body_base64"] = btoa(edited);

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "snapshot", "/snapshot_hash");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("mismatch");
    expect(diffs[0]!.expected).toBe(hash);
    expect(diffs[0]!.actual).not.toBe(hash);
  });

  it("names a broken inclusion proof", async () => {
    const { entry, bundle } = await files();
    const seal = entry["seal"] as Json;
    const proof = JSON.parse(seal["inclusion_proof"] as string) as {
      index: number;
      size: number;
      path: string[];
    };
    expect(proof.path.length).toBeGreaterThan(0);
    const step = proof.path[0]!;
    proof.path[0] = `${step.slice(0, -1)}${step.endsWith("a") ? "b" : "a"}`;
    seal["inclusion_proof"] = JSON.stringify(proof);

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "seal", "/seal/inclusion_proof");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("bad_proof");
  });

  it("names a proof string that is not a proof at all", async () => {
    const { entry, bundle } = await files();
    (entry["seal"] as Json)["inclusion_proof"] = "not a proof";

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    expect(find(report, "seal", "/seal/inclusion_proof")[0]!.reason).toBe(
      "malformed",
    );
  });

  it("names a validation signature made by another agent's key", async () => {
    const { entry, bundle, source } = await files();
    const events = bundle["events"] as Json[];
    const validation = events.find((event) => event["type"] === "validation")!;
    const payload = validation["payload"] as Json;
    const record = payload["record"] as Json;

    // The impostor is any agent that is not the one the record names.
    const impostor = Object.entries(source.keys).find(
      ([agent]) => agent !== record["agent"],
    )!;
    payload["signature"] = await signRecord(
      entry["id"] as string,
      "validation",
      record,
      impostor[1].privateKey,
    );

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const records = report.diffs.filter((diff) => diff.check === "records");
    expect(records).toHaveLength(1);
    expect(records[0]!.reason).toBe("bad_signature");
    expect(records[0]!.field).toBe(`/events/${validation["seq"] as number}`);
  });

  it("refuses an entry under a norm version the kernel does not implement", async () => {
    const { entry, bundle } = await files();
    entry["norm_version"] = "norm-v1.1";

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "snapshot", "/norm_version");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("unsupported_norm_version");
    // The recompute is refused, not faked: no snapshot_hash diff is invented.
    expect(find(report, "snapshot", "/snapshot_hash")).toHaveLength(0);
  });

  it("refuses a v0.6 core, naming the schema version it checks against", async () => {
    // Decision D-071: a core without `domain` was sealed under v0.7's
    // predecessor. It is still served, listed and synced exactly as it always
    // was; what the verifier will not do is check it against rules it never
    // claimed, so it says which version it checks against, exactly as
    // `unsupported_norm_version` does for the normalization rule.
    const { entry, bundle } = await files();
    delete entry["domain"];

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "schema", "/domain").filter(
      (diff) => diff.reason === "unsupported_schema_version",
    );
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.expected).toBe(SCHEMA_VERSION);
    expect(diffs[0]!.expected).toBe("v0.7");
    expect(diffs[0]!.actual).toBe("v0.6");
    expect(report.ok).toBe(false);
  });

  it("names a seal whose root no longer commits to the batch", async () => {
    const { entry, bundle } = await files();
    const seals = bundle["seals"] as Json[];
    seals[0]!["root"] = `sha256:${"0".repeat(64)}`;

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = report.diffs.filter((diff) => diff.check === "seals");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("bad_seal");
    expect(diffs[0]!.field).toBe("/seals/0");
  });

  it("names a seal position that does not point at the submission event", async () => {
    const { entry, bundle } = await files();
    (entry["seal"] as Json)["position"] = 0;

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "seal", "/seal/position");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("mismatch");
  });

  it("names witnesses the covering seal never carried", async () => {
    const { entry, bundle } = await files();
    (entry["seal"] as Json)["witnesses"] = ["not-a-countersignature"];

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "seal", "/seal/witnesses");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("mismatch");
  });

  it("replays the exclusions and names the refusal the door would have given", async () => {
    const { entry, bundle } = await files();
    // The registry no longer knows the validators' agents, so no record of
    // theirs could have been accepted at the door.
    (bundle["registry"] as Json)["agents"] = {};

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = report.diffs.filter((diff) => diff.check === "exclusions");
    expect(diffs).toHaveLength((entry["approvers"] as unknown[]).length);
    expect(diffs[0]!.reason).toBe("unregistered_agent");
    expect(diffs[0]!.field).toBe("/approvers/0");
  });

  it("names an approver's snapshot hash when its capture disagrees", async () => {
    const { entry, bundle } = await files();
    const claimed = `sha256:${"1".repeat(64)}`;
    ((entry["approvers"] as Json[])[0] as Json)["snapshot_hash"] = claimed;
    (bundle["captures"] as Record<string, Json>)[claimed] = {
      content_type: "text/plain",
      body_base64: btoa("a page that hashes to something else"),
    };

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "snapshot", "/approvers/0/snapshot_hash");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("mismatch");
    expect(diffs[0]!.expected).toBe(claimed);
  });

  it("says nothing about an approver capture the bundle simply does not hold", async () => {
    const { entry, bundle } = await files();
    ((entry["approvers"] as Json[])[0] as Json)["snapshot_hash"] =
      `sha256:${"2".repeat(64)}`;

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    // The validator's capture is optional; its absence is not a diff, and the
    // recompute is what names the edited record.
    expect(find(report, "snapshot", "/approvers/0/snapshot_hash")).toHaveLength(
      0,
    );
    expect(find(report, "derived", "/approvers")).toHaveLength(1);
  });

  it("names a capture the bundle does not carry", async () => {
    const { entry, bundle } = await files();
    bundle["captures"] = {};

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "snapshot", "/snapshot_hash");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("capture_missing");
  });
});

describe("verifyOffline: malformed files are diffs, never exceptions", () => {
  it("reports on a bundle that is not an object", async () => {
    const { entry } = await files();
    for (const bundle of [null, undefined, "a string", 42, []]) {
      const report = await verifyOffline(entry, bundle);
      expectWellFormed(report);
      expect(report.ok).toBe(false);
      expect(report.diffs.some((diff) => diff.check === "bundle")).toBe(true);
    }
  });

  it("reports on an entry that is not an object", async () => {
    const { bundle } = await files();
    for (const entry of [null, undefined, "a string", 42, []]) {
      const report = await verifyOffline(entry, bundle);
      expectWellFormed(report);
      expect(report.ok).toBe(false);
      expect(report.entry_id).toBeNull();
      expect(report.diffs.some((diff) => diff.check === "schema")).toBe(true);
    }
  });

  it("reports on a bundle missing its events", async () => {
    const { entry, bundle } = await files();
    delete bundle["events"];

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "bundle", "/events");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("missing");
    expect(report.entry_id).toBe(entry["id"]);
  });

  it("reports an entry whose id the log never submitted", async () => {
    const { entry, bundle } = await files();
    const events = bundle["events"] as Json[];
    bundle["events"] = events.filter(
      (event) => event["entry_id"] !== entry["id"],
    );

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const diffs = find(report, "core", "/id");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("not_submitted");
  });
});

describe("verifyOffline: a malformed element is a diff, never a TypeError", () => {
  it("names an element of events that is not an event", async () => {
    const { entry, bundle } = await files();
    const events = bundle["events"] as unknown[];
    const index = events.length;
    events.push(null);

    // The call returning at all is half the assertion: before the bundle check
    // read every element, this threw on `.seq` inside the sort.
    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    const diffs = find(report, "bundle", `/events/${index}`);
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("shape");
  });

  it("names a validation event whose payload is null", async () => {
    const { entry, bundle } = await files();
    const events = bundle["events"] as Json[];
    const index = events.findIndex((event) => event["type"] === "validation");
    expect(index).toBeGreaterThanOrEqual(0);
    // A prior decision with no payload: the exclusions replay used to read
    // `record` off it and throw.
    events[index]!["payload"] = null;

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    const diffs = find(report, "bundle", `/events/${index}`);
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("shape");
  });

  it("names an element of seals that is not a seal", async () => {
    const { entry, bundle } = await files();
    const seals = bundle["seals"] as unknown[];
    const index = seals.length;
    seals.push(null);

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    const diffs = find(report, "bundle", `/seals/${index}`);
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("shape");
  });
});

describe("verifyOffline: the two rules only a wider world can show", () => {
  it("names a validation by a provider, which no door would have taken", async () => {
    const source = await buildVerifyWorld({ withProvider: true });
    const agent = source.providerAgent;
    expect(agent).not.toBeNull();

    const signedAt = "2026-09-09T00:00:00.000Z";
    const record: ApproverRecord = {
      agent: agent!,
      operator: PROVIDER_OPERATOR,
      decision: "approve",
      reason: null,
      snapshot_hash: source.entry["snapshot_hash"] as string,
      assigned_random: false,
      test_accepted: null,
      reproduction: null,
      observation: null,
      signed_at: signedAt,
    };
    const index = source.bundle.events.filter(
      (event) =>
        event.type === "validation" && event.entry_id === source.entryId,
    ).length;
    const events: Event[] = await appendEvent(source.bundle.events, {
      at: signedAt,
      type: "validation",
      entry_id: source.entryId,
      payload: {
        record,
        signature: await signRecord(
          source.entryId,
          "validation",
          record,
          source.keys[agent!]!.privateKey,
        ),
      },
    });

    const report = await verifyOffline(clone(source.entry) as Json, {
      ...source.bundle,
      events,
    });
    expectWellFormed(report);
    const diffs = find(report, "exclusions", `/approvers/${index}`);
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("provider_operator");
  });

  it("verifies a world whose entry carries a reconfirmation", async () => {
    const source = await buildVerifyWorld({ withReconfirmation: true });
    expect((source.entry["reconfirmations"] as unknown[]).length).toBe(1);

    const report = await verifyOffline(
      clone(source.entry) as Json,
      clone(source.bundle),
    );
    expectWellFormed(report);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
  });

  it("names a reconfirmation whose signature was made as a validation", async () => {
    const source = await buildVerifyWorld({ withReconfirmation: true });
    const entry = clone(source.entry) as Json;
    const bundle = clone(source.bundle) as unknown as Json;
    const events = bundle["events"] as Json[];
    const event = events.find((one) => one["type"] === "reconfirmation")!;
    const payload = event["payload"] as Json;
    const record = payload["record"] as Json;
    // The kind is inside the signed bytes, so a validation signature can never
    // stand in for a reconfirmation's.
    payload["signature"] = await signRecord(
      source.entryId,
      "validation",
      record,
      source.keys[record["agent"] as string]!.privateKey,
    );

    const report = await verifyOffline(entry, bundle);
    expectWellFormed(report);
    const records = report.diffs.filter((diff) => diff.check === "records");
    expect(records).toHaveLength(1);
    expect(records[0]!.reason).toBe("bad_signature");
    expect(records[0]!.field).toBe(`/events/${event["seq"] as number}`);
  });
});

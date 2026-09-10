/**
 * The offline verifier's second half: the attestations (src/verify.ts).
 *
 * Whitepaper Section 8, "Drift attestation": "A probe set is drawn from
 * verified, observed, fresh entries by public randomness ... The model answers
 * the probes. Three operators from the trusted pool, none under the model's
 * operator, score its answers against the log and sign the result, and the
 * score and the probe hash are sealed with a date."
 *
 * Every clause of that is a fact about the log, so every clause is checkable
 * without asking anybody: the id the request hashes to, each score's signature
 * and signer, the hashes it pins, and the status and score the events fold to.
 * The shape of each test is the shape of the entry tests beside it — build a
 * real world, edit exactly one thing, and watch it named.
 */

import { describe, expect, it } from "vitest";

import { appendEvent, type Event } from "../src/index.js";
import { signRecord } from "../src/records.js";
import {
  ATTESTATION_CHECKS,
  verifyAttestations,
  type AttestationReport,
  type Diff,
} from "../src/verify.js";
import { buildVerifyWorld, type VerifyWorld } from "./helpers/verify-world.js";

type Json = Record<string, unknown>;

const SNAKE_CASE = /^[a-z][a-z0-9]*(_[a-z0-9]+)*$/;

/** Every diff, whatever else a test asserts, has to be readable by a stranger. */
function expectWellFormed(report: AttestationReport): void {
  expect(report.ok).toBe(
    report.attestations.every((one) => one.diffs.length === 0),
  );
  for (const one of report.attestations) {
    for (const diff of one.diffs) {
      expect(ATTESTATION_CHECKS).toContain(diff.check);
      expect(diff.field.startsWith("/")).toBe(true);
      expect(diff.reason).toMatch(SNAKE_CASE);
      expect(JSON.stringify(diff.expected ?? null).length).toBeLessThan(200);
      expect(JSON.stringify(diff.actual ?? null).length).toBeLessThan(200);
    }
  }
}

/** Every diff the report carries, whichever attestation carried it. */
function diffsOf(report: AttestationReport, check: string): Diff[] {
  return report.attestations.flatMap((one) =>
    one.diffs.filter((diff) => diff.check === check),
  );
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

/** The world's scored events, in the order the bundle carries them. */
function scoredEvents(bundle: Json): Json[] {
  return (bundle["events"] as Json[]).filter(
    (event) => event["type"] === "attestation_scored",
  );
}

/** One world per shape, built once: the tests copy the bundle and edit the copy. */
let clean: VerifyWorld | null = null;

async function world(): Promise<VerifyWorld> {
  if (clean === null) clean = await buildVerifyWorld({ withAttestation: true });
  return clean;
}

describe("verifyAttestations: the clean world", () => {
  it("takes an attestation drawn, answered and scored by its three scorers", async () => {
    const source = await world();
    const report = await verifyAttestations(clone(source.bundle));
    expectWellFormed(report);
    expect(report.attestations).toHaveLength(1);
    expect(report.attestations[0]!.id).toBe(source.attestation!.id);
    expect(report.attestations[0]!.status).toBe("scored");
    expect(report.attestations[0]!.diffs).toEqual([]);
    expect(report.ok).toBe(true);
  });

  it("says nothing about a log that holds no attestation at all", async () => {
    const plain = await buildVerifyWorld();
    const report = await verifyAttestations(clone(plain.bundle));
    expectWellFormed(report);
    expect(report.attestations).toEqual([]);
    expect(report.ok).toBe(true);
  });
});

describe("verifyAttestations: one edited field at a time", () => {
  it("names a flipped byte in a score's signature", async () => {
    const source = await world();
    const bundle = clone(source.bundle) as unknown as Json;
    const event = scoredEvents(bundle)[0]!;
    const payload = event["payload"] as Json;
    const signature = payload["signature"] as string;
    // The first character, not the last: base64url's final character of a
    // 64-byte signature carries padding bits, and flipping those can decode to
    // the same bytes.
    payload["signature"] = `${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;

    const report = await verifyAttestations(bundle as never);
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    const diffs = diffsOf(report, "attestation_signature");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("bad_signature");
    expect(diffs[0]!.field).toBe("/scores/0/signature");
  });

  it("names a scorer seated under the model's own operator", async () => {
    // Section 8: the score is "judged by parties its lab does not control".
    // The draw excludes the model's operator, so this state is one no honest
    // draw produces — which is exactly why the verifier must name it.
    const source = await buildVerifyWorld({ withAttestation: "model" });
    const report = await verifyAttestations(clone(source.bundle));
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    const diffs = diffsOf(report, "attestation_scorer");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("model_operator");
    expect(diffs[0]!.actual).toBe(source.attestation!.modelOperator);
  });

  it("names a score whose probe hash is not the probe set that was drawn", async () => {
    const source = await world();
    const bundle = clone(source.bundle) as unknown as Json;
    const event = scoredEvents(bundle)[1]!;
    const payload = event["payload"] as Json;
    const record = payload["record"] as Json;
    record["probe_hash"] = `sha256:${"0".repeat(64)}`;
    // Signed again over the edited record, so the signature check stays quiet
    // and the hash check is the only thing left to speak.
    payload["signature"] = await signRecord(
      source.attestation!.id,
      "attestation_score",
      record,
      source.keys[record["agent"] as string]!.privateKey,
    );

    const report = await verifyAttestations(bundle as never);
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    expect(diffsOf(report, "attestation_signature")).toEqual([]);
    const diffs = diffsOf(report, "attestation_hashes");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.field).toBe("/scores/1/probe_hash");
    expect(diffs[0]!.reason).toBe("mismatch");
  });

  it("names an expiry sitting on top of a complete score", async () => {
    // The sweep appends an expiry only to an attestation still open or
    // answered, so an `expired` over three signed scores is a status the
    // events themselves contradict.
    const source = await world();
    const events: Event[] = await appendEvent(source.bundle.events, {
      at: "2026-09-09T12:00:00.000Z",
      type: "attestation_expired",
      entry_id: null,
      payload: { attestation: source.attestation!.id, missing: [] },
    });

    const report = await verifyAttestations({ ...source.bundle, events });
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    expect(report.attestations[0]!.status).toBe("expired");
    const diffs = diffsOf(report, "attestation_derived");
    const status = diffs.filter((diff) => diff.field === "/status");
    expect(status).toHaveLength(1);
    expect(status[0]!.reason).toBe("mismatch");
    expect(status[0]!.expected).toBe("scored");
    expect(status[0]!.actual).toBe("expired");
    // And the score it should have published is gone with it.
    expect(diffs.filter((diff) => diff.field === "/score")).toHaveLength(1);
  });

  it("names an id the request does not hash to", async () => {
    const source = await world();
    const bundle = clone(source.bundle) as unknown as Json;
    for (const event of bundle["events"] as Json[]) {
      const payload = event["payload"] as Json;
      if (payload["attestation"] === undefined) continue;
      payload["attestation"] = "att_00000000000000000000000000000000";
    }

    const report = await verifyAttestations(bundle as never);
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    const diffs = diffsOf(report, "attestation_id");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.field).toBe("/id");
    expect(diffs[0]!.expected).toBe(source.attestation!.id);
  });

  it("names scores for an attestation nobody opened", async () => {
    const source = await world();
    const bundle = clone(source.bundle) as unknown as Json;
    bundle["events"] = (bundle["events"] as Json[]).filter(
      (event) => event["type"] !== "attestation_requested",
    );

    const report = await verifyAttestations(bundle as never);
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    expect(report.attestations[0]!.status).toBeNull();
    expect(report.attestations[0]!.diffs[0]!.reason).toBe("not_requested");
  });
});

describe("verifyAttestations: a malformed bundle is a diff, never an exception", () => {
  it("answers a bundle that is not a bundle at all", async () => {
    for (const bundle of [null, undefined, "a string", 42, [], {}]) {
      const report = await verifyAttestations(bundle as never);
      expectWellFormed(report);
      expect(report.attestations).toEqual([]);
      expect(report.ok).toBe(true);
    }
  });

  it("answers an attestation event whose payload is not an event's", async () => {
    const source = await world();
    const bundle = clone(source.bundle) as unknown as Json;
    const event = (bundle["events"] as Json[]).find(
      (one) => one["type"] === "attestation_requested",
    )!;
    (event["payload"] as Json)["scorers"] = "not a list of scorers";

    const report = await verifyAttestations(bundle as never);
    expectWellFormed(report);
    expect(report.ok).toBe(false);
    // The fold itself cannot read a scorer list that is a string, so the throw
    // it raises comes back as one named diff and never as a stack trace.
    const diffs = diffsOf(report, "attestation_derived");
    expect(diffs).toHaveLength(1);
    expect(diffs[0]!.reason).toBe("internal_error");
    expect(report.attestations[0]!.status).toBeNull();
  });
});

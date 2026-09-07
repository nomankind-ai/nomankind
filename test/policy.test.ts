import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  ASSIGNMENT_WINDOW_HOURS,
  CONTRIBUTOR_SHARE_PERCENT,
  FAILURE_REPORT_THRESHOLD,
  HOLDBACK_DAYS,
  NONCE_RETENTION_SECONDS,
  NORM_VERSION,
  POLICY,
  REQUEST_CLOCK_SKEW_SECONDS,
  READ_SHARE_SPLIT,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
  SEAL_INTERVAL_MINUTES,
  SEED_FEE_CAP_CENTS,
  SEED_FEE_RATE_CENTS,
  SLOT_COUNT,
  STALENESS_WINDOW_DAYS,
  TRUSTED_POOL_SWITCH,
} from "../src/policy.js";

const schemaPath = fileURLToPath(
  new URL("../schema/nomankind-entry-schema.json", import.meta.url),
);
const examplePath = fileURLToPath(
  new URL("../schema/nomankind-entry-example.json", import.meta.url),
);

const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as {
  properties: {
    category: { enum: string[] };
    norm_version: { pattern: string };
  };
};
const example = JSON.parse(readFileSync(examplePath, "utf8")) as {
  norm_version: string;
};

const EXPECTED_POLICY_KEYS = [
  "TRUSTED_POOL_SWITCH",
  "APPROVALS_TO_VERIFY_SMALL_POOL",
  "APPROVALS_TO_VERIFY_LARGE_POOL",
  "REJECTIONS_TO_REJECT",
  "VERIFICATION_MIN_OUTSIDE_OPERATORS",
  "ASSIGNMENT_WINDOW_HOURS",
  "REPRODUCTION_RUNS",
  "REPRODUCTION_HOLDS",
  "STALENESS_WINDOW_DAYS",
  "HOLDBACK_DAYS",
  "READ_SHARE_SPLIT",
  "SLOT_COUNT",
  "CONTRIBUTOR_SHARE_PERCENT",
  "SEAL_INTERVAL_MINUTES",
  "FAILURE_REPORT_THRESHOLD",
  "SEED_FEE_RATE_CENTS",
  "SEED_FEE_CAP_CENTS",
  "NORM_VERSION",
  "REQUEST_CLOCK_SKEW_SECONDS",
  "NONCE_RETENTION_SECONDS",
];

describe("policy numbers", () => {
  it("holds the lifecycle numbers from the whitepaper", () => {
    expect(TRUSTED_POOL_SWITCH).toBe(10);
    expect(ASSIGNMENT_WINDOW_HOURS).toBe(72);
    expect(REPRODUCTION_RUNS).toBe(10);
    expect(REPRODUCTION_HOLDS).toBe(8);
    expect(REPRODUCTION_HOLDS).toBeLessThanOrEqual(REPRODUCTION_RUNS);
    expect(SEAL_INTERVAL_MINUTES).toBe(5);
  });

  it("holds the money numbers from the whitepaper", () => {
    expect(HOLDBACK_DAYS).toBe(30);
    expect(READ_SHARE_SPLIT.submitter).toBe(15);
    expect(READ_SHARE_SPLIT.validator).toBe(5);
    expect(SLOT_COUNT).toBe(3);
    expect(CONTRIBUTOR_SHARE_PERCENT).toBe(30);
    expect(
      READ_SHARE_SPLIT.submitter + SLOT_COUNT * READ_SHARE_SPLIT.validator,
    ).toBe(CONTRIBUTOR_SHARE_PERCENT);
  });

  it("covers every category in the schema enum with a staleness window", () => {
    const categories = schema.properties.category.enum;
    expect(Object.keys(STALENESS_WINDOW_DAYS).sort()).toEqual(
      [...categories].sort(),
    );
    expect(STALENESS_WINDOW_DAYS.pricing).toBe(90);
    expect(STALENESS_WINDOW_DAYS.limit).toBe(90);
    expect(STALENESS_WINDOW_DAYS.behavior).toBe(30);
    for (const event of [
      "release",
      "deprecation",
      "outage",
      "misbehavior",
      "correction",
    ] as const) {
      expect(STALENESS_WINDOW_DAYS[event]).toBeNull();
    }
  });

  it("carries the maintainer's published amounts (D-032)", () => {
    expect(FAILURE_REPORT_THRESHOLD).toBe(3);
    expect(SEED_FEE_RATE_CENTS).toBe(100);
    expect(SEED_FEE_CAP_CENTS).toBe(10000);
  });

  it("states the D-032 amounts as positive integers", () => {
    for (const value of [
      FAILURE_REPORT_THRESHOLD,
      SEED_FEE_RATE_CENTS,
      SEED_FEE_CAP_CENTS,
    ]) {
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThan(0);
    }
  });

  it("caps a month of seed fees well above a single fee", () => {
    expect(SEED_FEE_CAP_CENTS % SEED_FEE_RATE_CENTS).toBe(0);
    expect(SEED_FEE_CAP_CENTS).toBeGreaterThan(SEED_FEE_RATE_CENTS);
  });

  it("no longer exports the retired null placeholders", async () => {
    const policyModule = (await import("../src/policy.js")) as Record<
      string,
      unknown
    >;
    expect(policyModule["SEED_FEE_RATE"]).toBeUndefined();
    expect(policyModule["SEED_FEE_CAP"]).toBeUndefined();
    expect(Object.keys(POLICY)).not.toContain("SEED_FEE_RATE");
    expect(Object.keys(POLICY)).not.toContain("SEED_FEE_CAP");
  });

  it("uses the norm version the example entry carries", () => {
    expect(NORM_VERSION).toBe("norm-v1.1");
    expect(NORM_VERSION).toBe(example.norm_version);
    expect(NORM_VERSION).toMatch(
      new RegExp(schema.properties.norm_version.pattern),
    );
  });

  it("holds the request authentication windows", () => {
    expect(REQUEST_CLOCK_SKEW_SECONDS).toBe(300);
    expect(NONCE_RETENTION_SECONDS).toBe(600);
    expect(NONCE_RETENTION_SECONDS).toBe(2 * REQUEST_CLOCK_SKEW_SECONDS);
  });

  it("collects every constant in a frozen POLICY object", () => {
    expect(Object.isFrozen(POLICY)).toBe(true);
    expect(Object.keys(POLICY).sort()).toEqual([...EXPECTED_POLICY_KEYS].sort());
  });

  it("exports only numbers, the norm version, and frozen objects", () => {
    for (const [key, value] of Object.entries(POLICY)) {
      expect(value).not.toBeNull();
      if (key === "NORM_VERSION") {
        expect(typeof value).toBe("string");
        continue;
      }
      if (typeof value === "object") {
        expect(Object.isFrozen(value)).toBe(true);
        continue;
      }
      expect(typeof value).toBe("number");
    }
  });

  it("keeps every named constant and its POLICY entry the same value", () => {
    expect(POLICY.TRUSTED_POOL_SWITCH).toBe(TRUSTED_POOL_SWITCH);
    expect(POLICY.ASSIGNMENT_WINDOW_HOURS).toBe(ASSIGNMENT_WINDOW_HOURS);
    expect(POLICY.REPRODUCTION_RUNS).toBe(REPRODUCTION_RUNS);
    expect(POLICY.REPRODUCTION_HOLDS).toBe(REPRODUCTION_HOLDS);
    expect(POLICY.STALENESS_WINDOW_DAYS).toBe(STALENESS_WINDOW_DAYS);
    expect(POLICY.HOLDBACK_DAYS).toBe(HOLDBACK_DAYS);
    expect(POLICY.READ_SHARE_SPLIT).toBe(READ_SHARE_SPLIT);
    expect(POLICY.SLOT_COUNT).toBe(SLOT_COUNT);
    expect(POLICY.CONTRIBUTOR_SHARE_PERCENT).toBe(CONTRIBUTOR_SHARE_PERCENT);
    expect(POLICY.SEAL_INTERVAL_MINUTES).toBe(SEAL_INTERVAL_MINUTES);
    expect(POLICY.FAILURE_REPORT_THRESHOLD).toBe(FAILURE_REPORT_THRESHOLD);
    expect(POLICY.SEED_FEE_RATE_CENTS).toBe(SEED_FEE_RATE_CENTS);
    expect(POLICY.SEED_FEE_CAP_CENTS).toBe(SEED_FEE_CAP_CENTS);
    expect(POLICY.NORM_VERSION).toBe(NORM_VERSION);
    expect(POLICY.REQUEST_CLOCK_SKEW_SECONDS).toBe(REQUEST_CLOCK_SKEW_SECONDS);
    expect(POLICY.NONCE_RETENTION_SECONDS).toBe(NONCE_RETENTION_SECONDS);
  });
});

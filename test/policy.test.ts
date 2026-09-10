import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  AGENT_ID_PREFIX,
  isAgentId,
  publicKeyFromAgentId,
} from "../src/identity.js";

import {
  ANCHOR_CALENDARS,
  ASSIGNMENT_WINDOW_HOURS,
  BEACON,
  CAPTURE_MAX_BYTES,
  CONTRIBUTOR_SHARE_PERCENT,
  FAILURE_REPORT_THRESHOLD,
  FETCH_MAX_REDIRECTS,
  FETCH_TIMEOUT_MS,
  HOLDBACK_DAYS,
  LIST_PAGE_LIMIT,
  DEFAULT_DOMAIN,
  DOMAINS,
  excludedPartyDomains,
  NONCE_RETENTION_SECONDS,
  NORM_VERSION,
  PAYOUT_CYCLE,
  PAYOUT_MINIMUM_MICROS,
  POLICY,
  READ_PRICE_MICROS_PER_READ,
  REGISTRY,
  REQUEST_CLOCK_SKEW_SECONDS,
  READ_SHARE_SPLIT,
  REPRODUCTION_HOLDS,
  REPRODUCTION_RUNS,
  SEAL_INTERVAL_MINUTES,
  SEAL_MAX_EVENTS,
  SCHEMA_VERSION,
  SLOT_COUNT,
  stalenessWindowDays,
  STANDING_ASSIGNMENT_MISSED,
  STANDING_DECAY_PAUSED,
  STANDING_DISPUTE_UPHELD,
  STANDING_OVERTURNED_SIGNER,
  STANDING_SUBMISSION_VERIFIED,
  STANDING_TRUSTED_ENTRY,
  STANDING_TRUSTED_STAY,
  STANDING_VALIDATION_ASSIGNED,
  STANDING_VALIDATION_VOLUNTEERED,
  SWEEP_INTERVAL_MINUTES,
  TRUSTED_POOL_SWITCH,
  WITNESSES_REQUIRED,
  WITNESS_FILE_TAIL_BYTES,
  WITNESS_PIN,
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
  "DOMAINS",
  "HOLDBACK_DAYS",
  "READ_SHARE_SPLIT",
  "SLOT_COUNT",
  "CONTRIBUTOR_SHARE_PERCENT",
  "SEAL_INTERVAL_MINUTES",
  "SWEEP_INTERVAL_MINUTES",
  "STATUS_ATTENTION_AFTER_INTERVALS",
  "STATUS_FAILING_AFTER_MINUTES",
  "WITNESSES_REQUIRED",
  "SEAL_MAX_EVENTS",
  "WITNESS_FILE_TAIL_BYTES",
  "REGISTRY",
  "WITNESS_PIN",
  "ANCHOR_CALENDARS",
  "FAILURE_REPORT_THRESHOLD",
  "DISPUTE_STAKE_STANDING",
  "DISPUTE_FILING_FEE_CENTS",
  "REVALIDATION_REQUEST_STAKE_STANDING",
  "REVALIDATION_REQUESTS_PER_OPERATOR_PER_WINDOW",
  "STANDING_VALIDATION_VOLUNTEERED",
  "STANDING_VALIDATION_ASSIGNED",
  "STANDING_SUBMISSION_VERIFIED",
  "STANDING_DISPUTE_UPHELD",
  "STANDING_OVERTURNED_SIGNER",
  "STANDING_ASSIGNMENT_MISSED",
  "STANDING_TRUSTED_ENTRY",
  "STANDING_TRUSTED_STAY",
  "STANDING_DECAY_PAUSED",
  "READ_PRICE_MICROS_PER_READ",
  "PAYOUT_MINIMUM_MICROS",
  "PAYOUT_CYCLE",
  "MIRROR",
  "NORM_VERSION",
  "SCHEMA_VERSION",
  "FETCH_MAX_REDIRECTS",
  "FETCH_TIMEOUT_MS",
  "CAPTURE_MAX_BYTES",
  "REQUEST_CLOCK_SKEW_SECONDS",
  "NONCE_RETENTION_SECONDS",
  "PROBE_SET_SIZE",
  "PROBE_SET_MIN_CANDIDATES",
  "ATTESTATION_SCORERS",
  "ATTESTATION_WINDOW_HOURS",
  "LIST_PAGE_LIMIT",
  "HOME_LATEST_ENTRIES",
  "LANDING_BAND_SEALS",
  "BEACON",
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

  it("covers every category of the default domain with a staleness window", () => {
    const categories = schema.properties.category.enum;
    const table = DOMAINS[DEFAULT_DOMAIN]!.staleness_window_days;
    expect(Object.keys(table).sort()).toEqual([...categories].sort());
    expect(stalenessWindowDays(DEFAULT_DOMAIN, "pricing")).toBe(90);
    expect(stalenessWindowDays(DEFAULT_DOMAIN, "limit")).toBe(90);
    expect(stalenessWindowDays(DEFAULT_DOMAIN, "behavior")).toBe(30);
    for (const event of [
      "release",
      "deprecation",
      "outage",
      "misbehavior",
      "correction",
    ] as const) {
      expect(stalenessWindowDays(DEFAULT_DOMAIN, event)).toBeNull();
    }
  });

  it("names the schema version in force beside the norm version", () => {
    expect(SCHEMA_VERSION).toBe("v0.7");
    expect(POLICY.SCHEMA_VERSION).toBe(SCHEMA_VERSION);
  });

  it("carries the maintainer's published amounts (D-032)", () => {
    expect(FAILURE_REPORT_THRESHOLD).toBe(3);
  });

  it("carries the sweep's own cadence, which is operational and not a rule", () => {
    // Five minutes, the same cadence wrangler.jsonc's cron names; the Sweeper
    // Durable Object sets its alarm from this and nowhere else. It says how
    // often the Worker looks, never how long a validator has.
    expect(SWEEP_INTERVAL_MINUTES).toBe(5);
    expect(Number.isInteger(SWEEP_INTERVAL_MINUTES)).toBe(true);
    expect(SWEEP_INTERVAL_MINUTES).toBeGreaterThan(0);
    // Far inside the window it helps enforce: a sweep that ran less often than
    // the deadline it closes would close deadlines late.
    expect(SWEEP_INTERVAL_MINUTES).toBeLessThan(ASSIGNMENT_WINDOW_HOURS * 60);
  });

  it("states the D-032 amounts as positive integers", () => {
    for (const value of [FAILURE_REPORT_THRESHOLD]) {
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThan(0);
    }
  });

  it("no longer exports the retired null placeholders", async () => {
    const policyModule = (await import("../src/policy.js")) as Record<
      string,
      unknown
    >;
    for (const name of [
      "SEED_FEE_RATE",
      "SEED_FEE_CAP",
      "SEED_FEE_RATE_CENTS",
      "SEED_FEE_CAP_CENTS",
    ]) {
      expect(policyModule[name]).toBeUndefined();
      expect(Object.keys(POLICY)).not.toContain(name);
    }
  });

  it("holds the norm version in force, which the example predates", () => {
    expect(NORM_VERSION).toBe("norm-v1.2");
    // The example entry was submitted under norm-v1.1 and its signed core
    // cannot change, so a new norm version leaves it where it is.
    expect(example.norm_version).toBe("norm-v1.1");
    const pattern = new RegExp(schema.properties.norm_version.pattern);
    expect(NORM_VERSION).toMatch(pattern);
    expect(example.norm_version).toMatch(pattern);
  });

  it("holds the snapshot fetch and archive limits", () => {
    // Step 1 of the norm rule: "Follow up to five redirects" and "Timeout
    // thirty seconds", stated in milliseconds because that is the unit a timer
    // takes.
    expect(FETCH_MAX_REDIRECTS).toBe(5);
    expect(FETCH_TIMEOUT_MS).toBe(30000);
    expect(FETCH_TIMEOUT_MS).toBe(30 * 1000);
    // The maintainer's own ceiling on what the Worker will archive: ten
    // mebibytes, not ten million bytes.
    expect(CAPTURE_MAX_BYTES).toBe(10485760);
    expect(CAPTURE_MAX_BYTES).toBe(10 * 1024 * 1024);
    for (const value of [FETCH_MAX_REDIRECTS, FETCH_TIMEOUT_MS, CAPTURE_MAX_BYTES]) {
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThan(0);
    }
  });

  it("holds the request authentication windows", () => {
    expect(REQUEST_CLOCK_SKEW_SECONDS).toBe(300);
    expect(NONCE_RETENTION_SECONDS).toBe(600);
    expect(NONCE_RETENTION_SECONDS).toBe(2 * REQUEST_CLOCK_SKEW_SECONDS);
  });

  it("holds the maintainer's published excluded-party list (Section 10)", () => {
    const providers = excludedPartyDomains(DEFAULT_DOMAIN);
    expect(Object.isFrozen(providers)).toBe(true);
    expect(providers).toContain("openai.com");
    expect(providers).toContain("anthropic.com");
    expect(providers).toContain("google.com");
    expect(providers.length).toBe(new Set(providers).size);
    // Every entry is a registrable domain, lowercase, with no scheme, no path
    // and no leading dot: the suffix check in src/registry.ts depends on it.
    for (const domain of providers) {
      expect(domain).toBe(domain.toLowerCase());
      expect(domain).toMatch(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/);
    }
  });

  it("holds the one page-size number", () => {
    expect(LIST_PAGE_LIMIT).toBe(100);
    expect(Number.isInteger(LIST_PAGE_LIMIT)).toBe(true);
    expect(LIST_PAGE_LIMIT).toBeGreaterThan(0);
  });

  it("pins the drand chain the draw reads", () => {
    expect(Object.isFrozen(BEACON)).toBe(true);
    expect(BEACON.endpoint).toBe("https://api.drand.sh");
    expect(BEACON.beacon_id).toBe("quicknet");
    expect(BEACON.chain_hash).toBe(
      "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    );
    // The chain hash is a SHA-256, written the way every hash in this system is.
    expect(BEACON.chain_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(BEACON.genesis_time).toBe(1692803367);
    expect(BEACON.period_seconds).toBe(3);
    for (const value of [BEACON.genesis_time, BEACON.period_seconds]) {
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThan(0);
    }
    // The endpoint is an origin and nothing else: the reader appends the chain
    // path to it, so a trailing slash or a path here would build a bad URL.
    expect(new URL(BEACON.endpoint).origin).toBe(BEACON.endpoint);
  });

  it("holds the seal's own numbers (Seal, and the witness bar)", () => {
    // The paper fixes the bar and states no count, so the count is the
    // maintainer's initial policy (D-054): one distinct pinned operator.
    expect(WITNESSES_REQUIRED).toBe(1);
    // The most events one seal covers; the next run continues from there.
    expect(SEAL_MAX_EVENTS).toBe(1000);
    // How much of a witness's growing JSONL file is read, from the end.
    expect(WITNESS_FILE_TAIL_BYTES).toBe(262144);
    expect(WITNESS_FILE_TAIL_BYTES).toBe(256 * 1024);
    for (const value of [
      WITNESSES_REQUIRED,
      SEAL_MAX_EVENTS,
      WITNESS_FILE_TAIL_BYTES,
    ]) {
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThan(0);
    }
  });

  it("pins the founding registry the seal fingerprint goes to", () => {
    expect(Object.isFrozen(REGISTRY)).toBe(true);
    expect(REGISTRY.origin).toBe("https://1f916.ai");
    expect(REGISTRY.public_key).toBe(
      "mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw",
    );
    expect(REGISTRY.log).toBe("identity_events");
    expect(REGISTRY.seal_label).toBe("nomankind-seal");
    // The origin is an origin and nothing else: the adapter appends /api/...
    // to it, so a trailing slash or a path here would build a bad URL.
    expect(new URL(REGISTRY.origin).origin).toBe(REGISTRY.origin);
    // The registry's key is an Ed25519 public key in the D-014 encoding.
    expect(publicKeyFromAgentId(AGENT_ID_PREFIX + REGISTRY.public_key)).toHaveLength(32);
    // The label the seal endpoint accepts: ^[a-z0-9._-]{1,64}$.
    expect(REGISTRY.seal_label).toMatch(/^[a-z0-9._-]{1,64}$/);
  });

  it("pins three witnesses under three operators (D-054)", () => {
    expect(Object.isFrozen(WITNESS_PIN)).toBe(true);
    expect(WITNESS_PIN).toHaveLength(3);
    expect(WITNESS_PIN.map((row) => row.id)).toEqual([6, 7, 8]);
    expect(WITNESS_PIN.map((row) => row.operator)).toEqual([
      "commonwealth",
      "head-of-experiments",
      "liveness",
    ]);
    // No two witnesses under common control is the whole bar, so three rows
    // that shared an operator would be one witness wearing three hats.
    expect(new Set(WITNESS_PIN.map((row) => row.operator)).size).toBe(3);
    expect(new Set(WITNESS_PIN.map((row) => row.public_key)).size).toBe(3);
    expect(new Set(WITNESS_PIN.map((row) => row.url)).size).toBe(3);
    for (const row of WITNESS_PIN) {
      expect(Object.isFrozen(row)).toBe(true);
      expect(Number.isInteger(row.id)).toBe(true);
      // Every key is a real Ed25519 public key in the encoding an agent id is
      // built from, so "1F916:" + the key is an identity and not a string.
      expect(publicKeyFromAgentId(AGENT_ID_PREFIX + row.public_key)).toHaveLength(32);
      expect(isAgentId(AGENT_ID_PREFIX + row.public_key)).toBe(true);
      // A published file, fetched over https and nothing else.
      expect(new URL(row.url).protocol).toBe("https:");
    }
    // Nomankind is ineligible, so none of its own keys may be pinned.
    expect(WITNESS_PIN.map((row) => row.operator)).not.toContain("nomankind");
  });

  it("pins the OpenTimestamps calendars the daily anchor tries", () => {
    expect(Object.isFrozen(ANCHOR_CALENDARS)).toBe(true);
    expect(ANCHOR_CALENDARS).toEqual([
      "https://a.pool.opentimestamps.org",
      "https://b.pool.opentimestamps.org",
      "https://alice.btc.calendar.opentimestamps.org",
      "https://bob.btc.calendar.opentimestamps.org",
      "https://finney.calendar.eternitywall.com",
    ]);
    expect(new Set(ANCHOR_CALENDARS).size).toBe(ANCHOR_CALENDARS.length);
    for (const calendar of ANCHOR_CALENDARS) {
      // Origins only: the adapter appends "/digest".
      expect(new URL(calendar).origin).toBe(calendar);
      expect(new URL(calendar).protocol).toBe("https:");
    }
  });

  it("collects every constant in a frozen POLICY object", () => {
    expect(Object.isFrozen(POLICY)).toBe(true);
    expect(Object.keys(POLICY).sort()).toEqual([...EXPECTED_POLICY_KEYS].sort());
  });

  it("holds the standing amounts, all integers (M21)", () => {
    // Section 9 names every move and states no amount, so all of these are the
    // maintainer's own placeholders. What the paper does fix is the ordering:
    // "assigned validations weigh more than volunteered ones".
    expect(STANDING_VALIDATION_ASSIGNED).toBeGreaterThan(
      STANDING_VALIDATION_VOLUNTEERED,
    );
    for (const value of [
      STANDING_VALIDATION_VOLUNTEERED,
      STANDING_VALIDATION_ASSIGNED,
      STANDING_SUBMISSION_VERIFIED,
      STANDING_DISPUTE_UPHELD,
      STANDING_OVERTURNED_SIGNER,
      STANDING_ASSIGNMENT_MISSED,
      STANDING_TRUSTED_ENTRY,
    ]) {
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThan(0);
    }
    // The stay threshold is the one that may be zero: falling below it means
    // owing more than you have earned.
    expect(Number.isInteger(STANDING_TRUSTED_STAY)).toBe(true);
    expect(STANDING_TRUSTED_STAY).toBeLessThanOrEqual(STANDING_TRUSTED_ENTRY);
  });

  it("pauses decay and publishes no rate for it", () => {
    // Section 9: decay "is paused until the paid loop starts (below), since
    // before then there is nothing for it to decay against". A rate of zero
    // would be a number nobody decided; the pause is the published fact.
    expect(STANDING_DECAY_PAUSED).toBe(true);
    expect(POLICY.STANDING_DECAY_PAUSED).toBe(STANDING_DECAY_PAUSED);
    for (const key of Object.keys(POLICY)) {
      expect(key).not.toMatch(/DECAY_RATE|DECAY_DAYS/);
    }
  });

  it("prices a read in micro-USD, at the paper's own example (M21)", () => {
    // "At $0.50 per thousand paid reads": fifty cents per thousand is five
    // hundred micro-USD per read, and the paper's worked example follows.
    expect(READ_PRICE_MICROS_PER_READ).toBe(500);
    expect(READ_PRICE_MICROS_PER_READ * 1000).toBe(500_000);
    const reads = 10_000;
    expect((reads * READ_PRICE_MICROS_PER_READ * READ_SHARE_SPLIT.submitter) / 100)
      .toBe(750_000);
    expect((reads * READ_PRICE_MICROS_PER_READ * READ_SHARE_SPLIT.validator) / 100)
      .toBe(250_000);
  });

  it("carries the payout floor and cycle (D-053)", () => {
    expect(PAYOUT_MINIMUM_MICROS).toBe(5_000_000);
    // Five dollars, in the micro-USD the ledger counts in.
    expect(PAYOUT_MINIMUM_MICROS).toBe(5 * 1_000_000);
    expect(Number.isInteger(PAYOUT_MINIMUM_MICROS)).toBe(true);
    expect(PAYOUT_CYCLE).toBe("monthly");
  });

  it("no longer carries a seed fee (D-052)", async () => {
    // "There is no seed fee: the maintainer pays nothing from its own funds,
    // and validating before revenue earns standing and read-share slots on the
    // entries validated, which pay from the first paid read."
    const policyModule = (await import("../src/policy.js")) as Record<
      string,
      unknown
    >;
    for (const key of Object.keys(POLICY)) expect(key).not.toMatch(/SEED_FEE/);
    for (const name of Object.keys(policyModule)) {
      expect(name).not.toMatch(/SEED_FEE/);
    }
  });

  it("exports only numbers, three names, one flag, and frozen objects", () => {
    for (const [key, value] of Object.entries(POLICY)) {
      expect(value).not.toBeNull();
      if (
        key === "NORM_VERSION" ||
        key === "PAYOUT_CYCLE" ||
        key === "SCHEMA_VERSION"
      ) {
        expect(typeof value).toBe("string");
        continue;
      }
      // Section 9 publishes the decay pause and no rate, so one entry is a
      // flag. It is the only one, and this is what keeps it that way.
      if (key === "STANDING_DECAY_PAUSED") {
        expect(typeof value).toBe("boolean");
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
    expect(POLICY.DOMAINS).toBe(DOMAINS);
    expect(POLICY.HOLDBACK_DAYS).toBe(HOLDBACK_DAYS);
    expect(POLICY.READ_SHARE_SPLIT).toBe(READ_SHARE_SPLIT);
    expect(POLICY.SLOT_COUNT).toBe(SLOT_COUNT);
    expect(POLICY.CONTRIBUTOR_SHARE_PERCENT).toBe(CONTRIBUTOR_SHARE_PERCENT);
    expect(POLICY.SEAL_INTERVAL_MINUTES).toBe(SEAL_INTERVAL_MINUTES);
    expect(POLICY.SWEEP_INTERVAL_MINUTES).toBe(SWEEP_INTERVAL_MINUTES);
    expect(POLICY.FAILURE_REPORT_THRESHOLD).toBe(FAILURE_REPORT_THRESHOLD);
    expect(POLICY.NORM_VERSION).toBe(NORM_VERSION);
    expect(POLICY.FETCH_MAX_REDIRECTS).toBe(FETCH_MAX_REDIRECTS);
    expect(POLICY.FETCH_TIMEOUT_MS).toBe(FETCH_TIMEOUT_MS);
    expect(POLICY.CAPTURE_MAX_BYTES).toBe(CAPTURE_MAX_BYTES);
    expect(POLICY.REQUEST_CLOCK_SKEW_SECONDS).toBe(REQUEST_CLOCK_SKEW_SECONDS);
    expect(POLICY.NONCE_RETENTION_SECONDS).toBe(NONCE_RETENTION_SECONDS);
    expect(POLICY.LIST_PAGE_LIMIT).toBe(LIST_PAGE_LIMIT);
    expect(POLICY.BEACON).toBe(BEACON);
    expect(POLICY.WITNESSES_REQUIRED).toBe(WITNESSES_REQUIRED);
    expect(POLICY.SEAL_MAX_EVENTS).toBe(SEAL_MAX_EVENTS);
    expect(POLICY.WITNESS_FILE_TAIL_BYTES).toBe(WITNESS_FILE_TAIL_BYTES);
    expect(POLICY.REGISTRY).toBe(REGISTRY);
    expect(POLICY.WITNESS_PIN).toBe(WITNESS_PIN);
    expect(POLICY.ANCHOR_CALENDARS).toBe(ANCHOR_CALENDARS);
    expect(POLICY.STANDING_VALIDATION_VOLUNTEERED).toBe(
      STANDING_VALIDATION_VOLUNTEERED,
    );
    expect(POLICY.STANDING_VALIDATION_ASSIGNED).toBe(STANDING_VALIDATION_ASSIGNED);
    expect(POLICY.STANDING_SUBMISSION_VERIFIED).toBe(STANDING_SUBMISSION_VERIFIED);
    expect(POLICY.STANDING_DISPUTE_UPHELD).toBe(STANDING_DISPUTE_UPHELD);
    expect(POLICY.STANDING_OVERTURNED_SIGNER).toBe(STANDING_OVERTURNED_SIGNER);
    expect(POLICY.STANDING_ASSIGNMENT_MISSED).toBe(STANDING_ASSIGNMENT_MISSED);
    expect(POLICY.STANDING_TRUSTED_ENTRY).toBe(STANDING_TRUSTED_ENTRY);
    expect(POLICY.STANDING_TRUSTED_STAY).toBe(STANDING_TRUSTED_STAY);
    expect(POLICY.READ_PRICE_MICROS_PER_READ).toBe(READ_PRICE_MICROS_PER_READ);
    expect(POLICY.PAYOUT_MINIMUM_MICROS).toBe(PAYOUT_MINIMUM_MICROS);
    expect(POLICY.PAYOUT_CYCLE).toBe(PAYOUT_CYCLE);
  });
});

/**
 * A draft the current schema cannot derive (decision D-124, items (b)).
 *
 * The newcomer dry run of 2026-09-13 followed the /dry-run guide, picked the
 * first entry the draft list offered, and ran `npm run validate` against it.
 * The entry was `nmk_8de6fec7` on demo, submitted under the pre-v0.7 schema:
 * its core carries seventeen keys and no `domain` (src/core.ts, `coreVersion`),
 * the entry schema requires that key, so the entry derived from it can never
 * validate. The door ran the whole validation, sealed nothing, and answered
 * 422 `schema_invalid` — which says the validator's own record was malformed
 * when it was not, and gives the operator nothing to do about it.
 *
 * Two promises here, and they are the two halves of the same fix: the door
 * names what is actually wrong, and the listing stops offering the work in the
 * first place. Both are pinned against miniflare's D1 with the real migrations,
 * because both are questions about a stored row.
 *
 * Nothing is hidden anywhere but the draft queue: a legacy entry that was
 * verified before v0.7 is still a fact the log stands behind, and the listings
 * that are not offers of work still show it.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { FixtureBeacon } from "../src/adapters/beacon.js";
import { CORE_KEYS, coreVersion, type Core } from "../src/core.js";
import { deriveEntry } from "../src/derive.js";
import { appendEvent, type ApproverRecord, type Event } from "../src/events.js";
import { DEFAULT_DOMAIN, NORM_VERSION } from "../src/policy.js";
import { signRecord } from "../src/records.js";
import type { D1Like } from "../src/storage/d1.js";
import {
  appendEvents,
  countEntries,
  listEntriesPage,
  putEntry,
} from "../src/storage/repository.js";
import type { Env } from "../src/worker/env.js";
import { handleRequest, type RequestDeps } from "../src/worker/index.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  FixtureResolver,
  makeAgent,
  signedPost,
  type TestAgent,
} from "./helpers/registry.js";

const NOW = new Date("2026-09-13T12:00:00.000Z");
const AT = NOW.toISOString();
const SUBMITTED_AT = "2026-09-08T09:00:00.000Z";

/** The draft written under v0.7: eighteen core keys, `domain` among them. */
const CURRENT_ID = `nmk_${"1".repeat(32)}`;
/** The draft written under v0.6: seventeen core keys and no `domain`. */
const LEGACY_ID = `nmk_${"8".repeat(32)}`;

const HASH = `sha256:${"a".repeat(64)}`;

let store: TestDatabase;
let db: D1Like;
let env: Env;
let deps: RequestDeps;
let validator: TestAgent;

const beacon = new FixtureBeacon("legacy-entry");

/** A v0.7 core: exactly the schema's eighteen signed keys. */
function currentCore(id: string): Core {
  const core: Record<string, unknown> = {
    id,
    subject: "example/kestrel-1",
    category: "pricing",
    domain: DEFAULT_DOMAIN,
    claim: "Kestrel seat pricing is $40 per seat per month.",
    before: "$35 per seat per month",
    after: "$40 per seat per month",
    effective_at: "2026-09-01",
    evidence_tier: "stated",
    evidence: null,
    observation: null,
    citation: "https://kestrel.example/pricing",
    snapshot_hash: HASH,
    norm_version: NORM_VERSION,
    supersedes: null,
    author: "1F916:YXV0aG9yX2s",
    author_operator: null,
    submitted_at: SUBMITTED_AT,
  };
  expect(Object.keys(core).sort()).toEqual([...CORE_KEYS].sort());
  return core as Core;
}

/**
 * A v0.6 core: the same fact, sealed before `domain` existed.
 *
 * The key is left out and never nulled — a seventeen-key core was signed as
 * seventeen keys, and adding an eighteenth with any value at all would change
 * its canonical form, its hash, its id and its signature (src/core.ts).
 */
function legacyCore(id: string): Core {
  const core: Record<string, unknown> = { ...currentCore(id), id };
  delete core["domain"];
  expect(coreVersion(core)).toBe("v0.6");
  return core as Core;
}

/** Seal both submissions onto one chain and store the drafts they derive to. */
async function storeDrafts(
  drafts: readonly (readonly [string, Core])[],
): Promise<void> {
  let events: Event[] = [];
  for (const [id, core] of drafts) {
    events = await appendEvent(events, {
      at: SUBMITTED_AT,
      type: "entry_submitted",
      entry_id: id,
      payload: { core, signature: "sig" },
    } as never);
  }
  await appendEvents(db, events);
  for (const [id] of drafts) {
    const derived = deriveEntry(events, id, { now: AT });
    expect(derived.entry["status"]).toBe("draft");
    await putEntry(
      db,
      derived.entry,
      derived.sidecar,
      events[events.length - 1]!.seq,
    );
  }
}

beforeAll(async () => {
  store = await openTestDatabase();
  db = store.db;
  validator = await makeAgent();

  // Sealed in submission order, so the listing's newest-first order is known.
  await storeDrafts([
    [LEGACY_ID, legacyCore(LEGACY_ID)],
    [CURRENT_ID, currentCore(CURRENT_ID)],
  ]);

  env = {
    DB: db,
    CAPTURES: store.captures,
    ENVIRONMENT: "local",
    MAINTAINER_AGENT_ID: "",
  } as unknown as Env;
  deps = {
    now: NOW,
    dns: new FixtureResolver({}),
    beacon,
  } as unknown as RequestDeps;
}, 600_000);

afterAll(async () => {
  await store?.dispose();
});

describe("the draft list stops offering entries no decision can verify", () => {
  it("leaves the legacy draft out of the draft page", async () => {
    const page = await listEntriesPage(db, { status: "draft", limit: 100 });
    expect(page.map((stored) => stored.entry["id"])).toEqual([CURRENT_ID]);
  });

  it("counts the draft total the listing actually shows", async () => {
    // The "n of m" line beside the listing: a total that counted a row the
    // page cannot show is a number nobody can reconcile with what they see.
    expect(await countEntries(db, { status: "draft" })).toBe(1);
  });

  it("hides it from the draft queue and from nowhere else", async () => {
    // The row is still there, still a draft, still readable: what changed is
    // which listing offers it as work.
    const all = await listEntriesPage(db, { limit: 100 });
    expect(all.map((stored) => stored.entry["id"]).sort()).toEqual(
      [CURRENT_ID, LEGACY_ID].sort(),
    );
    expect(await countEntries(db, {})).toBe(2);
  });
});

describe("the validate door on an entry the current schema cannot derive", () => {
  async function validate(
    id: string,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const record = {
      agent: validator.agentId,
      operator: "k1.example",
      decision: "approve",
      reason: null,
      snapshot_hash: HASH,
      assigned_random: false,
      test_accepted: null,
      reproduction: null,
      observation: null,
      signed_at: AT,
    } as unknown as ApproverRecord;
    const signature = await signRecord(
      id,
      "validation",
      record,
      validator.privateKey,
    );
    const request = await signedPost(validator, {
      path: `/entries/${id}/validate`,
      body: { record, signature },
      timestamp: AT,
    });
    const response = await handleRequest(request, env, { ...deps, now: NOW });
    return {
      status: response.status,
      body: (await response.json()) as Record<string, unknown>,
    };
  }

  it("refuses the legacy entry as legacy_entry, with a reason", async () => {
    const answer = await validate(LEGACY_ID);
    expect([answer.status, answer.body["error"]]).toEqual([422, "legacy_entry"]);
    expect(answer.body["core_version"]).toBe("v0.6");
    expect(typeof answer.body["reason"]).toBe("string");
    expect(answer.body["reason"]).toContain("domain");
  });

  it("still judges the validator's own record on an entry it can derive", async () => {
    // The same unregistered agent against the current entry: the door gets
    // past the legacy test and refuses on who is asking, which is what
    // `legacy_entry` must never be allowed to swallow.
    const answer = await validate(CURRENT_ID);
    expect(answer.status).toBe(422);
    expect(answer.body["error"]).not.toBe("legacy_entry");
  });
});

/**
 * The daily mirror: the claim on the day, what the export costs, and what it
 * deletes.
 *
 * Whitepaper Section 11 as the D-100 amendment left it: the sealed log goes out
 * once a UTC day to a public repository, and the Conclusion makes that the exit
 * right. Three things about that export are pinned here.
 *
 * The claim. 0014 wrote the day's row only after a successful push, so a run
 * killed mid-export left no trace and every later run that day started the whole
 * export again. The row now goes in `pending` before the export is built: a
 * claim younger than one sweep interval makes the next run stand down, an older
 * one it takes over, and a run that died costs one retry rather than all of
 * them.
 *
 * The cost. The export used to re-derive every entry from its own world, ten
 * statements an entry. It now reads the stored derived rows and falls back to
 * the derivation only for a row that is behind — and the two paths must produce
 * the same bytes, which is what the second half of this file holds by forcing
 * every row behind and diffing the push.
 *
 * The deletions. A push that only writes what changed never says that a file is
 * gone, so a path this environment's directory no longer writes is sent as a
 * null sha and nothing outside that directory is touched.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  GitHubMirrorAdapter,
  MockMirrorAdapter,
  type MirrorAdapter,
  type MirrorPush,
  type MirrorPushInput,
} from "../src/adapters/mirror.js";
import { appendEvent, buildSeal } from "../src/index.js";
import type { Event } from "../src/events.js";
import { gitBlobSha, type MirrorFile } from "../src/mirror.js";
import { SWEEP_INTERVAL_MINUTES } from "../src/policy.js";
import type { Seal } from "../src/seal.js";
import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import { registeredOperatorsAt } from "../src/derive.js";
import {
  appendEvents,
  claimMirror,
  eventsAfter,
  getEntry,
  latestMirror,
  mirrorClaimOn,
  putEntry,
  putMirror,
  putOperator,
  putSeal,
} from "../src/storage/repository.js";
import { mirrorStep } from "../src/worker/sweep.js";
import { entryWorld, rederive, worldAt } from "../src/worker/world.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import { buildVerifyWorld, type VerifyWorld } from "./helpers/verify-world.js";

/** The environment directory this export owns. */
const PREFIX = "demo";
/** How many entries the cost is measured over. */
const ENTRIES = 200;

/** When the log was sealed, and when the export runs: a release window apart. */
const SEAL_AT = "2026-08-01T00:00:00.000Z";
const EXPORT_AT = new Date("2026-09-12T12:00:00.000Z");
const MINUTE_MS = 60_000;

/** A seal four hundred days on, past every freshness window in this log. */
const LATE_SEAL_AT = "2027-09-05T00:00:00.000Z";
const LATE_EXPORT_AT = new Date("2027-10-20T12:00:00.000Z");

let store: TestDatabase;
let head = 0;
let newest: Seal;
/** Every submission in the log, so the rows can be seeded again. */
let submitted: Event<"entry_submitted">[] = [];

/** The four shapes a stored row can carry an answer its own events do not. */
const CHAIN_OLD = "nmk_01CHAINOLD";
const CHAIN_NEW = "nmk_01CHAINNEW";
const OVERTURNED = "nmk_01OVERTURNED";
const SAFETY_V1 = "nmk_01SAFETYV1";
const SAFETY_V2 = "nmk_01SAFETYV2";
const LEGACY = "nmk_01LEGACYV6";

/** Every statement a step prepared, with what it was bound to. */
function counting(db: D1Like): {
  db: D1Like;
  statements: { sql: string; values: unknown[] }[];
} {
  const statements: { sql: string; values: unknown[] }[] = [];
  const real = new WeakMap<D1LikeStatement, D1LikeStatement>();
  const wrap = (sql: string, statement: D1LikeStatement): D1LikeStatement => {
    const wrapped: D1LikeStatement = {
      bind: (...values: unknown[]) => {
        statements.push({ sql, values });
        return wrap(sql, statement.bind(...values));
      },
      first: <Row,>() => statement.first<Row>(),
      all: <Row,>() => statement.all<Row>(),
      run: <Row,>() => statement.run<Row>(),
    };
    real.set(wrapped, statement);
    return wrapped;
  };
  return {
    statements,
    db: {
      prepare: (sql: string) => {
        statements.push({ sql, values: [] });
        return wrap(sql, db.prepare(sql));
      },
      batch: (batched: D1LikeStatement[]) =>
        db.batch(batched.map((one) => real.get(one) ?? one)),
      exec: (sql: string) => db.exec(sql),
    },
  };
}

/**
 * A database holding the verifier's own world plus two hundred more entries,
 * sealed, with every entry's row derived the way the sweep's own steps derive
 * it — over the entry's world at the sealed head, at the newest seal's instant.
 */
beforeAll(async () => {
  const world: VerifyWorld = await buildVerifyWorld({ now: SEAL_AT });
  let events: Event[] = [...world.bundle.events].sort(
    (left, right) => left.seq - right.seq,
  );

  const submission = events.find(
    (event) => event.type === "entry_submitted" && event.entry_id === world.entryId,
  ) as Event<"entry_submitted">;

  /** The decisions that carried the verifier's own entry to verified. */
  const decisions = events.filter(
    (event) => event.type === "validation" && event.entry_id === world.entryId,
  );

  const submit = async (
    id: string,
    over: Record<string, unknown>,
    drop: readonly string[] = [],
  ): Promise<void> => {
    const core = { ...submission.payload.core, id, ...over } as Record<
      string,
      unknown
    >;
    for (const key of drop) delete core[key];
    events = await appendEvent(events, {
      at: SEAL_AT,
      type: "entry_submitted",
      entry_id: id,
      payload: {
        core: core as typeof submission.payload.core,
        signature: submission.payload.signature,
      },
    });
  };

  /** The same decisions again, on another entry: what carries it to verified. */
  const judge = async (id: string): Promise<void> => {
    for (const decision of decisions) {
      events = await appendEvent(events, {
        at: SEAL_AT,
        type: "validation",
        entry_id: id,
        payload: decision.payload as Event<"validation">["payload"],
      });
    }
  };

  for (let index = 0; index < ENTRIES; index += 1) {
    await submit(`nmk_01MIRROR${String(index).padStart(6, "0")}`, {
      subject: `example/kestrel-${index}`,
    });
  }

  // A superseded chain, an overturned entry, a version-stale pair in another
  // domain and a core from before the schema named a domain. Every one of them
  // is a shape the stored row records an answer for that the entry's own events
  // alone do not carry — `superseded_by` comes from a later entry, `overturned`
  // from a dispute, D-096's staleness from a sibling — which is exactly where a
  // row the export trusts could disagree with the derivation it replaces.
  await submit(CHAIN_OLD, { subject: "example/chain" });
  await judge(CHAIN_OLD);
  await submit(CHAIN_NEW, { subject: "example/chain", supersedes: CHAIN_OLD });
  await judge(CHAIN_NEW);

  await submit(OVERTURNED, { subject: "example/overturned" });
  await judge(OVERTURNED);
  events = await appendEvent(events, {
    at: SEAL_AT,
    type: "dispute_upheld",
    entry_id: OVERTURNED,
    payload: { correction_entry_id: CHAIN_NEW },
  });

  await submit(SAFETY_V1, {
    domain: "ai-safety",
    category: "conduct_observed",
    subject: "acme/guard/v1",
  });
  await judge(SAFETY_V1);
  await submit(SAFETY_V2, {
    domain: "ai-safety",
    category: "conduct_observed",
    subject: "acme/guard/v2",
  });
  await judge(SAFETY_V2);

  // v0.6 named no domain at all, and `domainOf` answers ai-ecosystem for it.
  await submit(LEGACY, { subject: "example/legacy" }, ["domain"]);

  store = await openTestDatabase();
  await appendEvents(store.db, events);

  head = events[events.length - 1]!.seq;
  const registered = registeredOperatorsAt(events, head);
  for (const id of registered.operators) {
    await putOperator(store.db, {
      id,
      maintainer: registered.maintainers.has(id),
      provider: false,
      registeredSeq: 0,
      details: {},
    });
  }

  const seals = [...world.bundle.seals].sort((left, right) => left.seq - right.seq);
  for (const seal of seals) await putSeal(store.db, seal);
  const built = await buildSeal(events, seals[seals.length - 1] ?? null, {
    now: SEAL_AT,
  });
  if (!built.ok) throw new Error(`mirror-claim: buildSeal ${built.reason}`);
  await putSeal(store.db, built.seal);
  newest = built.seal;

  submitted = events.filter(
    (event) => event.type === "entry_submitted" && event.entry_id !== null,
  ) as Event<"entry_submitted">[];
  // Twice. `supersedersOf` and the version-sibling walk read the `entries`
  // table, so the first pass derives a target before the entry that supersedes
  // it has a row to be found by — which is not what the doors do: the decision
  // that verifies a superseder rewrites its target's row in the same batch. The
  // second pass is that rewrite, and it is what a live store always holds.
  await seedRows(new Date(newest.sealed_at));
  await seedRows(new Date(newest.sealed_at));
}, 600_000);

/**
 * Every entry's stored row, derived exactly as the sweep's staleness step
 * derives one: over the entry's world at the sealed head, at an instant. This is
 * the row the export is allowed to trust, and re-seeding it is how a test that
 * put every row behind hands the next one a store that is current again.
 */
async function seedRows(asOf: Date): Promise<void> {
  for (const event of submitted) {
    const id = event.entry_id!;
    const one = worldAt(await entryWorld(store.db, id), head);
    const derived = rederive(one, id, asOf);
    const through = one.entryEvents.reduce(
      (last, each) => Math.max(last, each.seq),
      event.seq,
    );
    await putEntry(store.db, derived.entry, derived.sidecar, through);
  }
}

afterAll(async () => {
  await store?.dispose();
});

/** Forget every export this day, so the next step claims the day afresh. */
async function forgetTheDay(): Promise<void> {
  await store.db.prepare(`DELETE FROM mirrors`).run();
}

function step(
  db: D1Like,
  adapter: MirrorAdapter,
  now: Date,
): ReturnType<typeof mirrorStep> {
  return mirrorStep(db, PREFIX, adapter, now, now.toISOString(), () => {});
}

/** An adapter that dies inside the push, after the day has been claimed. */
class DyingMirrorAdapter implements MirrorAdapter {
  readonly kind = "mock";
  pushes = 0;
  async push(_input: MirrorPushInput): Promise<MirrorPush> {
    this.pushes += 1;
    throw new Error("the isolate went away mid-push");
  }
}

describe("the day is claimed before it is pushed", () => {
  it("retries a killed export once the interval has passed, not before", async () => {
    await forgetTheDay();
    const dying = new DyingMirrorAdapter();
    await expect(step(store.db, dying, EXPORT_AT)).rejects.toThrow(
      "the isolate went away mid-push",
    );
    expect(dying.pushes).toBe(1);

    // The claim outlived the run that made it, and the day is not exported.
    const claim = await mirrorClaimOn(store.db, "2026-09-12");
    expect(claim?.state).toBe("pending");
    expect(claim?.head).toBe(head);
    expect(await latestMirror(store.db)).toBeNull();

    // Inside the interval the next run stands down rather than paying for the
    // whole export again, which is what every run of the day used to do.
    const tooSoon = new MockMirrorAdapter();
    const skips: string[] = [];
    const early = await mirrorStep(
      store.db,
      PREFIX,
      tooSoon,
      new Date(EXPORT_AT.getTime() + MINUTE_MS),
      new Date(EXPORT_AT.getTime() + MINUTE_MS).toISOString(),
      (reason) => skips.push(reason),
    );
    expect(skips).toEqual(["mirror_pending"]);
    expect(early.report).toBeNull();
    expect(tooSoon.commits).toBe(0);

    // Past it, the next run takes the day over and the export lands.
    const later = new MockMirrorAdapter();
    const taken = await step(
      store.db,
      later,
      new Date(EXPORT_AT.getTime() + (SWEEP_INTERVAL_MINUTES + 1) * MINUTE_MS),
    );
    expect(taken.report?.date).toBe("2026-09-12");
    expect(later.commits).toBe(1);
    expect((await mirrorClaimOn(store.db, "2026-09-12"))?.state).toBe("pushed");
    expect((await latestMirror(store.db))?.date).toBe("2026-09-12");
  }, 600_000);

  it("stands down on a day that is already pushed", async () => {
    const skips: string[] = [];
    const again = new MockMirrorAdapter();
    await mirrorStep(
      store.db,
      PREFIX,
      again,
      new Date(EXPORT_AT.getTime() + 2 * SWEEP_INTERVAL_MINUTES * MINUTE_MS),
      EXPORT_AT.toISOString(),
      (reason) => skips.push(reason),
    );
    expect(skips).toEqual(["mirror_current"]);
    expect(again.commits).toBe(0);
  }, 600_000);
});

describe("the export reads the rows it already has", () => {
  it("costs a handful of statements at two hundred entries", async () => {
    await forgetTheDay();
    const measured = counting(store.db);
    const mirror = new MockMirrorAdapter();
    const done = await step(measured.db, mirror, EXPORT_AT);
    expect(done.report).not.toBeNull();

    const prepared = measured.statements.filter(
      (statement) => statement.values.length === 0,
    );
    // Ten statements an entry would be two thousand. The export is the pages it
    // reads: the entries, where their events stop, the seals, the anchors, the
    // operators, the sealed log and the attestations, plus the one gathering the
    // D-096-stale entry sends back to the events. Measured at forty and pinned
    // just above it, so a regression that doubled the work fails here.
    expect(prepared.length).toBeLessThanOrEqual(45);
  }, 600_000);

  it("pushes the bytes the full derivation would have pushed", async () => {
    await forgetTheDay();
    const fast = new MockMirrorAdapter();
    await step(store.db, fast, EXPORT_AT);

    // Every row put behind the sealed head, which is the one condition the
    // export falls back to deriving the entry from its own world under.
    await store.db.prepare(`UPDATE entries SET derived_through_seq = 0`).run();
    await forgetTheDay();
    const slow = new MockMirrorAdapter();
    await step(store.db, slow, EXPORT_AT);

    expect([...slow.files.keys()].sort()).toEqual([...fast.files.keys()].sort());
    for (const [path, content] of fast.files) {
      expect(slow.files.get(path)).toBe(content);
    }
    expect(fast.files.size).toBeGreaterThan(ENTRIES);

    // And the world it agreed over really held the four shapes, rather than two
    // hundred copies of one: a byte-identity that only ever compared drafts
    // would pass whatever the two paths did with a superseded target.
    const exported = (id: string): Record<string, unknown> =>
      JSON.parse(fast.files.get(`${PREFIX}/entries/${id}.json`)!).entry as Record<
        string,
        unknown
      >;
    expect([
      exported(CHAIN_OLD)["status"],
      exported(CHAIN_OLD)["superseded_by"],
    ]).toEqual(["superseded", CHAIN_NEW]);
    expect([
      exported(OVERTURNED)["status"],
      exported(OVERTURNED)["overturned_by"],
    ]).toEqual(["overturned", CHAIN_NEW]);
    // D-096: a later version of the same model verified, so the older one is
    // stale — a fact about the log and not about any clock.
    expect([exported(SAFETY_V1)["domain"], exported(SAFETY_V1)["stale"]]).toEqual([
      "ai-safety",
      true,
    ]);
    expect(exported(SAFETY_V2)["stale"]).toBe(false);
    // A v0.6 core names no domain at all and is exported as it was signed.
    expect("domain" in exported(LEGACY)).toBe(false);
  }, 600_000);
});

describe("two overlapping runs, one day", () => {
  it("gives the day to exactly one of them", async () => {
    await forgetTheDay();
    const stale = new Date(
      EXPORT_AT.getTime() - SWEEP_INTERVAL_MINUTES * MINUTE_MS,
    ).toISOString();
    const claim = (started: Date): Promise<boolean> =>
      claimMirror(store.db, {
        date: "2026-09-12",
        started_at: started.toISOString(),
        head,
        seal_seq: newest.seq,
        take_over_before: stale,
      });

    // Both timers reach the claim with the day untouched. The insert wins for
    // one of them and the other's update finds a claim that is not yet stale,
    // so the export is built once rather than twice.
    const both = await Promise.all([
      claim(EXPORT_AT),
      claim(new Date(EXPORT_AT.getTime() + 1)),
    ]);
    expect(both.filter(Boolean).length).toBe(1);
    expect((await mirrorClaimOn(store.db, "2026-09-12"))?.state).toBe("pending");

    // A claim older than the interval is a run that died, and is taken over —
    // once. Two runs racing for an abandoned day is the same race again.
    const later = new Date(
      EXPORT_AT.getTime() + 2 * SWEEP_INTERVAL_MINUTES * MINUTE_MS,
    );
    const takeOver = (started: Date): Promise<boolean> =>
      claimMirror(store.db, {
        date: "2026-09-12",
        started_at: started.toISOString(),
        head,
        seal_seq: newest.seq,
        take_over_before: new Date(
          later.getTime() - SWEEP_INTERVAL_MINUTES * MINUTE_MS,
        ).toISOString(),
      });
    const raced = await Promise.all([
      takeOver(later),
      takeOver(new Date(later.getTime() + 1)),
    ]);
    expect(raced.filter(Boolean).length).toBe(1);

    // And a day that is pushed is never claimed, whatever the clock says.
    await putMirror(store.db, {
      date: "2026-09-12",
      exported_at: EXPORT_AT.toISOString(),
      commit: "commit",
      tree: "tree",
      head,
      seal_seq: newest.seq,
      entries: 0,
      files_changed: 0,
      url: "https://example.test/tree",
      raw_url: "https://example.test/raw",
    });
    expect(await takeOver(new Date(later.getTime() + 2))).toBe(false);
    expect((await mirrorClaimOn(store.db, "2026-09-12"))?.state).toBe("pushed");
  }, 600_000);
});

// ---------------------------------------------------------------------------
// The clock the export reads
// ---------------------------------------------------------------------------

describe("an entry whose window closes between the seal and the export", () => {
  it("is exported stale, exactly as the derivation would have it", async () => {
    // A later seal, four hundred days on: every pricing entry of this log has a
    // window that ended inside it, and the rows still say what they said when
    // they were derived. The export's clock is the newest seal's, so a row taken
    // as it stands would publish an entry as fresh that `GET /sync` calls stale
    // at that same position — one entry at one position described two ways.
    const events = await eventsAfter(store.db, -1, 10_000);
    const tail = await appendEvent(events, {
      at: LATE_SEAL_AT,
      type: "read_count",
      entry_id: null,
      payload: {
        date: "2027-09-05",
        reads: [],
        total: 0,
        counter_first: 1,
        counter_last: 0,
      },
    });
    await appendEvents(store.db, [tail[tail.length - 1]!]);
    const built = await buildSeal(tail, newest, { now: LATE_SEAL_AT });
    if (!built.ok) throw new Error(`mirror-claim: buildSeal ${built.reason}`);
    await putSeal(store.db, built.seal);
    newest = built.seal;
    head = built.seal.last_seq;

    // The rows as the doors left them, on the clock they were written at: fresh.
    await seedRows(new Date(SEAL_AT));
    await seedRows(new Date(SEAL_AT));
    const plain = `nmk_01MIRROR${String(0).padStart(6, "0")}`;
    const row = await getEntry(store.db, plain);
    expect((row!.entry as unknown as Record<string, unknown>)["stale"]).toBe(false);

    await forgetTheDay();
    const fast = new MockMirrorAdapter();
    const done = await step(store.db, fast, LATE_EXPORT_AT);
    expect(done.report).not.toBeNull();

    const exported = JSON.parse(
      fast.files.get(`${PREFIX}/entries/${plain}.json`)!,
    ) as { entry: Record<string, unknown> };
    expect(exported.entry["stale"]).toBe(true);

    // And the whole export is still what deriving every entry from its own
    // world at this head and this clock produces.
    await store.db.prepare(`UPDATE entries SET derived_through_seq = 0`).run();
    await forgetTheDay();
    const slow = new MockMirrorAdapter();
    await step(store.db, slow, LATE_EXPORT_AT);
    expect([...slow.files.keys()].sort()).toEqual([...fast.files.keys()].sort());
    for (const [path, content] of fast.files) {
      expect(slow.files.get(path)).toBe(content);
    }
  }, 600_000);
});

// ---------------------------------------------------------------------------
// Dropped paths
// ---------------------------------------------------------------------------

const API = "https://api.test";
const REPOSITORY = "nomankind-ai/log-test";
const BRANCH = "trunk";

interface Call {
  readonly url: string;
  readonly method: string;
  readonly body: unknown;
}

/** A repository table: each url answers a status and a JSON body. */
function repository(table: Record<string, { status: number; body?: unknown }>): {
  fetch: typeof fetch;
  calls: Call[];
} {
  const calls: Call[] = [];
  const fetchFn = async function (
    this: unknown,
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    if (this !== undefined && this !== globalThis) {
      throw new TypeError("Illegal invocation");
    }
    const url = String(input);
    calls.push({
      url,
      method: init?.method ?? "GET",
      body: typeof init?.body === "string" ? JSON.parse(init.body) : null,
    });
    const answer = table[url];
    if (answer === undefined) throw new TypeError(`unroutable: ${url}`);
    return new Response(
      answer.body === undefined ? "" : JSON.stringify(answer.body),
      { status: answer.status, headers: { "content-type": "application/json" } },
    );
  } as unknown as typeof fetch;
  return { fetch: fetchFn, calls };
}

describe("a stale file is deleted by the next push", () => {
  it("sends a null sha for it and touches nothing outside the directory", async () => {
    const files: readonly MirrorFile[] = [
      { path: "index.json", content: "[]\n" },
      { path: "mirror.json", content: '{\n  "format": "nomankind-mirror-v3"\n}\n' },
    ];
    const stale = "entries/nmk_01V2ERA.json";
    const trees = `${API}/repos/${REPOSITORY}/git/trees/${BRANCH}?recursive=1`;
    const writeTree = `${API}/repos/${REPOSITORY}/git/trees`;

    const { fetch: fetchFn, calls } = repository({
      [trees]: {
        status: 200,
        body: {
          sha: "tree-at-head",
          truncated: false,
          tree: [
            ...(await Promise.all(
              files.map(async (file) => ({
                path: `${PREFIX}/${file.path}`,
                type: "blob",
                sha: await gitBlobSha(file.content),
              })),
            )),
            {
              path: `${PREFIX}/${stale}`,
              type: "blob",
              sha: "a-v2-era-entry-file",
            },
            { path: "LICENSE", type: "blob", sha: "license-sha" },
            {
              path: "production/index.json",
              type: "blob",
              sha: "the-other-environment",
            },
          ],
        },
      },
      [`${API}/repos/${REPOSITORY}/git/ref/heads/${BRANCH}`]: {
        status: 200,
        body: { object: { sha: "commit-at-head" } },
      },
      [writeTree]: { status: 201, body: { sha: "tree-just-written" } },
      [`${API}/repos/${REPOSITORY}/git/commits`]: {
        status: 201,
        body: { sha: "commit-just-written" },
      },
      [`${API}/repos/${REPOSITORY}/git/refs/heads/${BRANCH}`]: {
        status: 200,
        body: { object: { sha: "commit-just-written" } },
      },
    });

    const pushed = await new GitHubMirrorAdapter({
      token: "ghp_never_logged",
      fetch: fetchFn,
      repository: REPOSITORY,
      branch: BRANCH,
      api: API,
    }).push({ prefix: PREFIX, files, message: "mirror demo" });

    expect(pushed.ok).toBe(true);
    // Nothing changed, and the push happened anyway: the deletion is the change.
    expect(pushed.ok && pushed.changed).toBe(1);

    const written = calls.find((call) => call.url === writeTree)!;
    const tree = (written.body as { tree: Record<string, unknown>[] }).tree;
    expect(tree).toEqual([
      { path: `${PREFIX}/${stale}`, mode: "100644", type: "blob", sha: null },
    ]);
  });

  it("records the deletion on the mock the sweep tests push to", async () => {
    const mirror = new MockMirrorAdapter();
    await mirror.push({
      prefix: PREFIX,
      files: [{ path: "index.json", content: "[]\n" }],
      message: "first",
    });
    mirror.files.set(`${PREFIX}/entries/gone.json`, "{}\n");
    mirror.files.set("production/index.json", "[]\n");

    await mirror.push({
      prefix: PREFIX,
      files: [{ path: "index.json", content: "[]\n" }],
      message: "second",
    });

    expect(mirror.deleted).toEqual([`${PREFIX}/entries/gone.json`]);
    expect(mirror.files.has(`${PREFIX}/entries/gone.json`)).toBe(false);
    expect(mirror.files.has("production/index.json")).toBe(true);
  });
});

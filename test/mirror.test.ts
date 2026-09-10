/**
 * The mirror layout, and the rows that record an export.
 *
 * Whitepaper Section 11, "Deployment and status": the sealed log goes out daily
 * to a public repository under CC0, and the Conclusion says why — "the exit is
 * not a promise, it is a copy". A copy is only worth having if it is the same
 * copy every time, so most of what is pinned here is byte-identity: two builds
 * of one sealed head produce the same files in the same order with the same
 * bytes, or a quiet day would show a diff and nobody could tell a real change
 * from a re-serialization.
 *
 * The world is the offline verifier's own (test/helpers/verify-world.ts): real
 * Ed25519 keys, real signatures, real hashes, one real seal over everything up
 * to the decisions, and a draft submitted after it so the "nothing unsealed is
 * ever exported" rule has something to leave out. Nothing here is hand-written
 * except the two malformed inputs the layout is supposed to refuse.
 *
 * The storage half opens a real miniflare D1 and applies every migration, 0014
 * included, so the mirrors table is the one the deploy will create.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { buildSeal, deriveEntry, entryHash, extractCore } from "../src/index.js";
import type { Event } from "../src/events.js";
import type { Seal } from "../src/seal.js";
import type { Anchor } from "../src/anchor.js";
import {
  MIRROR_FORMAT,
  MirrorError,
  buildMirror,
  gitBlobSha,
  mirrorDiff,
  mirrorUrls,
  type MirrorEntryRecord,
  type MirrorFile,
  type MirrorInput,
  type MirrorOperator,
} from "../src/mirror.js";
import {
  DOMAIN_SLUGS,
  MIRROR,
  NORM_VERSION,
  SCHEMA_VERSION,
} from "../src/policy.js";
import {
  entryIdsThrough,
  latestMirror,
  mirrorOn,
  putMirror,
  type MirrorRecord,
} from "../src/storage/repository.js";
import { openTestDatabase, type TestDatabase } from "./helpers/d1.js";
import {
  VERIFIED_ENTRY_ID,
  DRAFT_ENTRY_ID,
  buildVerifyWorld,
  type VerifyWorld,
} from "./helpers/verify-world.js";

/** The instant every export in this file is made at. */
const EXPORTED_AT = "2026-09-11T00:04:00.000Z";
const ENVIRONMENT = "demo";

let world: VerifyWorld;
/** The single seal the world makes, and the events it covers. */
let firstSeal: Seal;
let sealedEvents: Event[];
let entries: MirrorEntryRecord[];

/** One entry as the export carries it: derived at the sealed head. */
async function record(
  events: readonly Event[],
  entryId: string,
  asOf: string,
): Promise<MirrorEntryRecord> {
  const derived = deriveEntry([...events], entryId, { now: asOf });
  return {
    entry: derived.entry,
    sidecar: derived.sidecar,
    entry_hash: await entryHash(extractCore(derived.entry)),
  };
}

/** The operators of the world, as the layout takes them. */
function operators(): MirrorOperator[] {
  const registry = world.bundle.registry;
  const byOperator = new Map<string, string[]>();
  for (const [agent, operator] of Object.entries(registry.agents)) {
    byOperator.set(operator, [...(byOperator.get(operator) ?? []), agent]);
  }
  return Object.entries(registry.operators).map(([operator, row]) => ({
    operator,
    maintainer: row.maintainer,
    provider: row.provider,
    trusted: !row.maintainer,
    domains: [...(row.domains ?? [])],
    agents: byOperator.get(operator) ?? [],
  }));
}

/** The whole input, at the world's one seal. */
function input(over: Partial<MirrorInput> = {}): MirrorInput {
  return {
    environment: ENVIRONMENT,
    exported_at: EXPORTED_AT,
    seals: [firstSeal],
    anchors: [],
    events: sealedEvents,
    entries,
    operators: operators(),
    ...over,
  };
}

/** One file's content by path, or a failure naming the path that is missing. */
function contentOf(files: readonly MirrorFile[], path: string): string {
  const found = files.find((file) => file.path === path);
  if (found === undefined) throw new Error(`no file at ${path}`);
  return found.content;
}

/** A JSON file's parsed body. */
function jsonOf(files: readonly MirrorFile[], path: string): unknown {
  return JSON.parse(contentOf(files, path));
}

/** A JSONL file's parsed lines. */
function linesOf(files: readonly MirrorFile[], path: string): unknown[] {
  const content = contentOf(files, path);
  if (content === "") return [];
  return content
    .slice(0, -1)
    .split("\n")
    .map((line) => JSON.parse(line));
}

beforeAll(async () => {
  world = await buildVerifyWorld();
  const seals = world.bundle.seals;
  expect(seals).toHaveLength(1);
  firstSeal = seals[0]!;
  sealedEvents = world.bundle.events.filter(
    (event) => event.seq <= firstSeal.last_seq,
  );
  entries = [
    await record(sealedEvents, VERIFIED_ENTRY_ID, firstSeal.sealed_at),
  ];
}, 60_000);

describe("the layout", () => {
  it("writes exactly the files the format names, sorted by path", () => {
    const files = buildMirror(input());
    expect(files.map((file) => file.path)).toEqual([
      "anchors.jsonl",
      `entries/${VERIFIED_ENTRY_ID}.json`,
      `events/${String(firstSeal.seq).padStart(8, "0")}.jsonl`,
      "index.json",
      "mirror.json",
      "operators.json",
      "seals.jsonl",
    ]);
  });

  it("builds the same bytes twice from the same sealed head", () => {
    // The whole point of the mirror: a day on which nothing happened must show
    // no diff, which is only true if the export is a function of the head.
    expect(buildMirror(input())).toEqual(buildMirror(input()));
  });

  it("ends every document with one newline and indents JSON by two", () => {
    const files = buildMirror(input());
    for (const file of files) {
      if (file.content === "") continue;
      expect([file.path, file.content.endsWith("\n")]).toEqual([file.path, true]);
      expect([file.path, file.content.endsWith("\n\n")]).toEqual([
        file.path,
        false,
      ]);
    }
    expect(contentOf(files, "mirror.json")).toContain('\n  "format"');
  });

  it("says what it is, at which head, under which license", () => {
    const manifest = jsonOf(buildMirror(input()), "mirror.json") as Record<
      string,
      unknown
    >;
    expect(manifest).toEqual({
      format: MIRROR_FORMAT,
      environment: ENVIRONMENT,
      exported_at: EXPORTED_AT,
      as_of: firstSeal.sealed_at,
      head: firstSeal.last_seq,
      seal_seq: firstSeal.seq,
      seals: 1,
      events: firstSeal.size,
      entries: 1,
      operators: operators().length,
      schema_version: SCHEMA_VERSION,
      norm_version: NORM_VERSION,
      domains: [...DOMAIN_SLUGS],
      captures_base: "https://demo.nomankind.ai/captures/",
      code: `${MIRROR.web}/nomankind-ai/nomankind`,
      verify: `npm run verify-mirror -- ../log/${ENVIRONMENT}`,
      license: MIRROR.license,
    });
    // The license is policy's and never a literal typed beside the manifest.
    expect(manifest["license"]).toBe(MIRROR.license);
  });

  it("splits the events by seal, each file holding exactly its own range", async () => {
    // A second seal over what the first left, so the split is a real split
    // rather than one file that happens to hold everything.
    const rest = world.bundle.events.filter(
      (event) => event.seq > firstSeal.last_seq,
    );
    expect(rest.length).toBeGreaterThan(0);
    const built = await buildSeal(world.bundle.events, firstSeal, {
      now: "2026-09-10T01:00:00.000Z",
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const second = built.seal;

    const files = buildMirror(
      input({
        seals: [firstSeal, second],
        events: world.bundle.events,
        entries: [
          ...entries,
          await record(world.bundle.events, DRAFT_ENTRY_ID, second.sealed_at),
        ],
      }),
    );

    const firstFile = linesOf(
      files,
      `events/${String(firstSeal.seq).padStart(8, "0")}.jsonl`,
    ) as Event[];
    const secondFile = linesOf(
      files,
      `events/${String(second.seq).padStart(8, "0")}.jsonl`,
    ) as Event[];
    expect(firstFile.map((event) => event.seq)).toEqual(
      sealedEvents.map((event) => event.seq),
    );
    expect(secondFile.map((event) => event.seq)).toEqual(
      rest.map((event) => event.seq),
    );
    // The first seal's file is byte-identical to the one the single-seal export
    // wrote: a seal's range never moves, so a seal's file never changes.
    expect(contentOf(files, `events/${String(firstSeal.seq).padStart(8, "0")}.jsonl`))
      .toBe(
        contentOf(
          buildMirror(input()),
          `events/${String(firstSeal.seq).padStart(8, "0")}.jsonl`,
        ),
      );
  });

  it("indexes the entries in position order, with the covering seal", () => {
    const files = buildMirror(input());
    const index = jsonOf(files, "index.json") as Record<string, unknown>[];
    expect(index).toHaveLength(1);
    const row = index[0]!;
    const entry = world.entry as unknown as Record<string, unknown>;
    expect(row["id"]).toBe(VERIFIED_ENTRY_ID);
    expect(row["subject"]).toBe(entry["subject"]);
    expect(row["category"]).toBe(entry["category"]);
    expect(row["tier"]).toBe(entry["evidence_tier"]);
    expect(row["status"]).toBe("verified");
    expect(row["seal_seq"]).toBe(firstSeal.seq);
    expect(row["entry_hash"]).toBe(entries[0]!.entry_hash);
    const submitted = sealedEvents.find(
      (event) =>
        event.type === "entry_submitted" && event.entry_id === VERIFIED_ENTRY_ID,
    );
    expect(row["position"]).toBe(submitted!.seq);
    // The positions rise, which is what "in position order" means with more
    // than one row and what a reader paging the index relies on.
    const positions = index.map((one) => one["position"] as number);
    expect([...positions].sort((left, right) => left - right)).toEqual(positions);
  });

  it("exports nothing the seals do not cover", async () => {
    // The draft was submitted after the seal, so its submission is not among the
    // sealed events and it is not part of the sealed record.
    const files = buildMirror(
      input({
        entries: [
          ...entries,
          await record(world.bundle.events, DRAFT_ENTRY_ID, firstSeal.sealed_at),
        ],
      }),
    );
    expect(files.map((file) => file.path)).not.toContain(
      `entries/${DRAFT_ENTRY_ID}.json`,
    );
    const manifest = jsonOf(files, "mirror.json") as Record<string, unknown>;
    expect(manifest["entries"]).toBe(1);
  });

  it("carries every entry with its sidecar and its hash", () => {
    const files = buildMirror(input());
    expect(jsonOf(files, `entries/${VERIFIED_ENTRY_ID}.json`)).toEqual({
      entry: entries[0]!.entry,
      sidecar: entries[0]!.sidecar,
      entry_hash: entries[0]!.entry_hash,
    });
  });

  it("carries the registry the offline verifier needs, plus trusted", () => {
    const files = buildMirror(input());
    const written = jsonOf(files, "operators.json") as {
      operators: Record<string, unknown>[];
      agents: Record<string, string>;
    };
    expect(written.operators.map((one) => one["operator"])).toEqual(
      [...operators().map((one) => one.operator)].sort(),
    );
    expect(written.agents).toEqual(world.bundle.registry.agents);
    for (const row of written.operators) {
      expect(Object.keys(row)).toEqual([
        "operator",
        "maintainer",
        "provider",
        "trusted",
        "domains",
        "agents",
      ]);
    }
  });

  it("writes the seals and the anchors in order, one document per line", () => {
    const anchors: Anchor[] = [
      {
        date: "2026-09-09",
        first_seal_seq: 0,
        last_seal_seq: 0,
        roots: [firstSeal.root],
        hash: "sha256:" + "0".repeat(64),
        external: null,
      },
      {
        date: "2026-09-08",
        first_seal_seq: null,
        last_seal_seq: null,
        roots: [],
        hash: "sha256:" + "1".repeat(64),
        external: null,
      },
    ];
    const files = buildMirror(input({ anchors }));
    expect(linesOf(files, "seals.jsonl")).toEqual([
      JSON.parse(JSON.stringify(firstSeal)),
    ]);
    // Date order, whatever order the caller paged them in.
    expect(
      (linesOf(files, "anchors.jsonl") as Anchor[]).map((one) => one.date),
    ).toEqual(["2026-09-08", "2026-09-09"]);
  });

  it("writes an empty jsonl for a day with no anchor at all", () => {
    expect(contentOf(buildMirror(input()), "anchors.jsonl")).toBe("");
  });
});

describe("what the layout refuses", () => {
  it("refuses no_seal on a log nothing has sealed", () => {
    expect(() => buildMirror(input({ seals: [], events: [] }))).toThrow(
      MirrorError,
    );
    try {
      buildMirror(input({ seals: [], events: [] }));
      expect.unreachable("buildMirror accepted a log with no seal");
    } catch (error) {
      expect((error as MirrorError).reason).toBe("no_seal");
    }
  });

  it("refuses gap when the events do not cover a seal's own range", () => {
    // One event of the seal's range dropped: the seal commits to it, so an
    // export built from this read is missing something a verifier will look for.
    const holed = sealedEvents.filter(
      (event) => event.seq !== firstSeal.last_seq,
    );
    try {
      buildMirror(input({ events: holed }));
      expect.unreachable("buildMirror accepted events with a hole in them");
    } catch (error) {
      expect(error).toBeInstanceOf(MirrorError);
      expect((error as MirrorError).reason).toBe("gap");
    }
  });
});

describe("git blob names", () => {
  it("computes the sha git computes", async () => {
    // `printf 'hello\n' | git hash-object --stdin`.
    expect(await gitBlobSha("hello\n")).toBe(
      "ce013625030ba8dba906f756967f9e9ca394464a",
    );
    // The empty blob, which git also has a well-known name for.
    expect(await gitBlobSha("")).toBe(
      "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
    );
  });

  it("names a file by its bytes and not by its path", async () => {
    expect(await gitBlobSha("a\n")).not.toBe(await gitBlobSha("b\n"));
    expect(await gitBlobSha("a\n")).toBe(await gitBlobSha("a\n"));
  });
});

describe("the diff", () => {
  it("answers nothing when every path is already exactly these bytes", async () => {
    const files = buildMirror(input());
    const existing = new Map<string, string>();
    for (const file of files) existing.set(file.path, await gitBlobSha(file.content));
    expect(await mirrorDiff(files, existing)).toEqual([]);
  });

  it("answers the paths that are absent or changed, and only those", async () => {
    const files = buildMirror(input());
    const existing = new Map<string, string>();
    for (const file of files) existing.set(file.path, await gitBlobSha(file.content));
    existing.delete("index.json");
    existing.set("mirror.json", await gitBlobSha("something else\n"));
    const changed = await mirrorDiff(files, existing);
    expect(changed.map((file) => file.path)).toEqual([
      "index.json",
      "mirror.json",
    ]);
  });

  it("answers everything against an empty repository", async () => {
    const files = buildMirror(input());
    expect(await mirrorDiff(files, new Map())).toEqual(files);
  });
});

describe("where an export can be read", () => {
  it("pins both links to the commit rather than to the branch", () => {
    const urls = mirrorUrls("abc123", "production");
    expect(urls).toEqual({
      url: `${MIRROR.web}/${MIRROR.repository}/tree/abc123/production`,
      raw_url: `${MIRROR.raw}/${MIRROR.repository}/abc123/production/mirror.json`,
    });
    expect(urls.url).not.toContain(MIRROR.branch);
  });
});

describe("the mirrors table (migration 0014)", () => {
  let store: TestDatabase;

  const row = (over: Partial<MirrorRecord> = {}): MirrorRecord => ({
    date: "2026-09-11",
    exported_at: EXPORTED_AT,
    commit: "commit-one",
    tree: "tree-one",
    head: 42,
    seal_seq: 3,
    entries: 7,
    files_changed: 5,
    url: "https://github.com/nomankind-ai/log/tree/commit-one/demo",
    raw_url:
      "https://raw.githubusercontent.com/nomankind-ai/log/commit-one/demo/mirror.json",
    ...over,
  });

  beforeAll(async () => {
    store = await openTestDatabase();
  }, 60_000);

  afterAll(async () => {
    await store?.dispose();
  });

  it("answers null before anything has been exported", async () => {
    expect(await latestMirror(store.db)).toBeNull();
    expect(await mirrorOn(store.db, "2026-09-11")).toBeNull();
  });

  it("keeps one row per day and reads it back whole", async () => {
    await putMirror(store.db, row());
    expect(await mirrorOn(store.db, "2026-09-11")).toEqual(row());
    expect(await latestMirror(store.db)).toEqual(row());
  });

  it("replaces the day rather than adding a second row for it", async () => {
    await putMirror(store.db, row({ commit: "commit-two", files_changed: 0 }));
    expect(await mirrorOn(store.db, "2026-09-11")).toEqual(
      row({ commit: "commit-two", files_changed: 0 }),
    );
    const counted = await store.db
      .prepare(`SELECT COUNT(*) AS n FROM mirrors`)
      .first<{ n: number }>();
    expect(counted!.n).toBe(1);
  });

  it("reads the newest day by the day and not by the order written", async () => {
    await putMirror(store.db, row({ date: "2026-09-09", commit: "older" }));
    await putMirror(store.db, row({ date: "2026-09-12", commit: "newest" }));
    await putMirror(store.db, row({ date: "2026-09-10", commit: "middle" }));
    expect((await latestMirror(store.db))!.date).toBe("2026-09-12");
    expect((await mirrorOn(store.db, "2026-09-09"))!.commit).toBe("older");
  });

  it("answers no entry ids on a database with no entries", async () => {
    expect(
      await entryIdsThrough(store.db, { throughSeq: 100, limit: 10 }),
    ).toEqual([]);
  });
});

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

import {
  appendEvent,
  buildSeal,
  deriveEntry,
  entryHash,
  extractCore,
  signRecord,
} from "../src/index.js";
import type { LedgerRow } from "../src/ledger.js";
import { STANDING_FORMULA, standingAt } from "../src/standing.js";
import type { Event } from "../src/events.js";
import type { Seal } from "../src/seal.js";
import type { Anchor } from "../src/anchor.js";
import {
  MIRROR_FORMAT,
  MIRROR_FORMATS,
  MirrorError,
  buildMirror,
  gitBlobSha,
  mirrorAttestations,
  mirrorDiff,
  mirrorFormatOf,
  mirrorLedgerRows,
  mirrorStanding,
  mirrorUrls,
  v1Sidecar,
  type MirrorAttestationAnswers,
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
  CHALLENGER_OPERATOR,
  CORRECTION_ENTRY_ID,
  OUTSIDE_OPERATORS,
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

/** The operators of one world, as the layout takes them. */
function operatorsOf(one: VerifyWorld): MirrorOperator[] {
  const registry = one.bundle.registry;
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

/** The operators of the file's own world. */
function operators(): MirrorOperator[] {
  return operatorsOf(world);
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
    attestations: [],
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
      "ledger.jsonl",
      "mirror.json",
      "operators.json",
      "seals.jsonl",
      "standing.json",
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
      attestations: 0,
      standing_position: firstSeal.last_seq,
      ledger_rows: 0,
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

  it("names the layout it writes and the older one it still knows", () => {
    // Two formats rather than one moving one. A mirror is CC0 and already
    // cloned: the copies pulled before the three families and the sidecar's
    // source class joined the export are somebody's exit, and the reader that
    // refused them for being old would be taking that exit back.
    expect(MIRROR_FORMAT).toBe("nomankind-mirror-v2");
    expect(MIRROR_FORMATS).toEqual([
      "nomankind-mirror-v1",
      "nomankind-mirror-v2",
    ]);
    expect(jsonOf(buildMirror(input()), "mirror.json")).toMatchObject({
      format: "nomankind-mirror-v2",
    });
    expect(mirrorFormatOf("nomankind-mirror-v1")).toBe("v1");
    expect(mirrorFormatOf("nomankind-mirror-v2")).toBe("v2");
    expect(mirrorFormatOf("nomankind-mirror-v3")).toBeNull();
    expect(mirrorFormatOf(null)).toBeNull();
  });

  it("reads a v1 sidecar as every key but the one v1 never had", () => {
    const sidecar = {
      effective_tier: "stated",
      revalidations: [],
      source: { class: "official", matched_host: null, provider: null },
    };
    expect(v1Sidecar(sidecar)).toEqual({
      effective_tier: "stated",
      revalidations: [],
    });
    // Over a value that is not a sidecar at all it is the value: a malformed
    // file is the caller's difference to name, never this function's.
    expect(v1Sidecar(null)).toBeNull();
    expect(v1Sidecar([1])).toEqual([1]);
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

/**
 * The three families the export recomputes rather than reads.
 *
 * A richer world than the file's own: the verifier's, with the reconfirmation,
 * the challenge and the drift attestation it can be built with, plus one day of
 * published read counts appended to it — and a second seal over all of that, so
 * everything the fold is about is inside the sealed record rather than above it.
 *
 * Nothing here is asserted against a hand-written expectation of what the money
 * or the standing should be. What is pinned is that the files are what the
 * kernel's own folds say (`standingAt`, `deriveAttestation`, src/ledger.ts), in
 * the order the log put the events in, and that two builds are the same bytes.
 */
describe("attestations, standing and the ledger", () => {
  /** The day the read counts were published for, in the pre-M24 shape. */
  const READ_DAY = "2026-09-09";
  const READS = 10_000;
  /**
   * A second day, published in the M24 shape: the whole day's traffic in
   * `reads` and the half that was billed in `paid`. The two numbers differ on
   * purpose, so a fold that priced the wrong one could not pass by accident.
   */
  const PAID_DAY = "2026-09-08";
  const PAID_DAY_READS = 600;
  const PAID_DAY_PAID = 250;
  const PAID_KEY = "key_0123456789abcdef";
  const RICH_SEALED_AT = "2026-09-10T02:00:00.000Z";

  let rich: VerifyWorld;
  let richEvents: Event[];
  let richSeals: Seal[];
  let files: MirrorFile[];
  let answers: MirrorAttestationAnswers[];
  let attestationId = "";
  let head = 0;

  /** The whole input, at the second seal. */
  function richInput(over: Partial<MirrorInput> = {}): MirrorInput {
    return {
      environment: ENVIRONMENT,
      exported_at: EXPORTED_AT,
      seals: richSeals,
      anchors: [],
      events: richEvents,
      entries: richEntries,
      operators: operatorsOf(rich),
      attestations: answers,
      ...over,
    };
  }

  let richEntries: MirrorEntryRecord[] = [];

  beforeAll(async () => {
    rich = await buildVerifyWorld({
      withAttestation: true,
      withDispute: "outsider",
      withReconfirmation: true,
    });
    attestationId = rich.attestation!.id;

    // One published day of reads on the verified entry, so the ledger fold has
    // money to price rather than only stakes.
    // The M24 day first: free reads beside paid ones, and only the paid half
    // is money. Published before the pre-M24 day in log order so the file holds
    // both shapes and neither is the last word.
    richEvents = await appendEvent(rich.bundle.events, {
      at: "2026-09-10T00:20:00.000Z",
      type: "read_count",
      entry_id: null,
      payload: {
        date: PAID_DAY,
        reads: [{ entry_id: VERIFIED_ENTRY_ID, count: PAID_DAY_READS }],
        total: PAID_DAY_READS,
        counter_first: 1,
        counter_last: PAID_DAY_READS,
        paid: {
          reads: [{ entry_id: VERIFIED_ENTRY_ID, count: PAID_DAY_PAID }],
          total: PAID_DAY_PAID,
          keys: { [PAID_KEY]: PAID_DAY_PAID },
        },
      },
    });
    richEvents = await appendEvent(richEvents, {
      at: "2026-09-10T00:30:00.000Z",
      type: "read_count",
      entry_id: null,
      payload: {
        date: READ_DAY,
        reads: [{ entry_id: VERIFIED_ENTRY_ID, count: READS }],
        total: READS,
        counter_first: PAID_DAY_READS + 1,
        counter_last: PAID_DAY_READS + READS,
      },
    });

    const first = rich.bundle.seals[0]!;
    const built = await buildSeal(richEvents, first, { now: RICH_SEALED_AT });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    richSeals = [first, built.seal];
    head = built.seal.last_seq;

    richEntries = [
      await record(richEvents, VERIFIED_ENTRY_ID, built.seal.sealed_at),
      await record(richEvents, DRAFT_ENTRY_ID, built.seal.sealed_at),
      await record(richEvents, CORRECTION_ENTRY_ID, built.seal.sealed_at),
    ];
    answers = [
      {
        attestation: attestationId,
        answers: [{ entry_id: VERIFIED_ENTRY_ID, answer: "the claim" }],
      },
    ];
    files = buildMirror(richInput());
  }, 120_000);

  it("writes one file per attestation the sealed events opened", () => {
    expect(files.map((file) => file.path)).toContain(
      `attestations/${attestationId}.json`,
    );
    const written = jsonOf(files, `attestations/${attestationId}.json`) as {
      attestation: Record<string, unknown>;
      answers: unknown;
    };
    // The record is the fold's, not a copy of anything: the same one
    // `GET /attestations/{id}` serves, recomputed at the sealed head.
    expect(written.attestation).toEqual(
      JSON.parse(
        JSON.stringify(
          mirrorAttestations(richEvents, answers, richSeals[1]!.sealed_at)[0]!
            .attestation,
        ),
      ),
    );
    expect(written.attestation["id"]).toBe(attestationId);
    expect(written.attestation["status"]).toBe("scored");
    // The answers are the one thing the log does not carry, so they travel from
    // the caller and nowhere else.
    expect(written.answers).toEqual([
      { entry_id: VERIFIED_ENTRY_ID, answer: "the claim" },
    ]);
  });

  it("leaves out an attestation whose request the seals do not cover", () => {
    // The first seal alone covers only the registry and the decisions, so the
    // attestation opened after it is not part of that sealed record.
    const only = buildMirror(
      richInput({
        seals: [rich.bundle.seals[0]!],
        entries: [richEntries[0]!],
      }),
    );
    expect(only.map((file) => file.path)).not.toContain(
      `attestations/${attestationId}.json`,
    );
    expect(
      (jsonOf(only, "mirror.json") as Record<string, unknown>)["attestations"],
    ).toBe(0);
  });

  it("writes standing as GET /standing computes it, sorted by operator id", () => {
    const written = jsonOf(files, "standing.json") as {
      position: number;
      formula: string[];
      operators: { operator: string; standing: number }[];
    };
    expect(written.position).toBe(head);
    expect(written.formula).toEqual([...STANDING_FORMULA]);

    const expected = standingAt(richEvents, head);
    expect(written.operators.map((one) => one.operator)).toEqual(
      [...expected.keys()].sort(),
    );
    for (const row of written.operators) {
      expect([row.operator, row.standing]).toEqual([
        row.operator,
        expected.get(row.operator)!.standing,
      ]);
    }
    expect(mirrorStanding(richEvents, head)).toEqual({
      position: head,
      formula: STANDING_FORMULA,
      operators: written.operators,
    });
  });

  it("prices the published day and carries the stake the challenge put up", () => {
    const rows = linesOf(files, "ledger.jsonl") as LedgerRow[];
    expect(rows.length).toBeGreaterThan(0);

    // In log order: the challenge was filed before the day was published.
    const kinds = rows.map((row) => row.kind);
    expect(kinds).toContain("dispute_stake");
    expect(kinds).toContain("read_share");
    expect(kinds.indexOf("dispute_stake")).toBeLessThan(
      kinds.indexOf("read_share"),
    );
    // The reconciliation closes each day it reconciles.
    expect(kinds[kinds.length - 1]).toBe("reconciliation");

    const shares = rows.filter((row) => row.kind === "read_share");
    expect(shares.every((row) => row.entry_id === VERIFIED_ENTRY_ID)).toBe(true);
    expect(shares.some((row) => row.role === "submitter")).toBe(true);

    // The pre-M24 day carries no paid block at all, and every read it published
    // was billed for: the whole of `reads` is what it meant when it was sealed,
    // so that is what the mirror's fold prices — the same number the sweep's
    // ledger step wrote, because both call src/ledger.ts's one function.
    const plain = shares.filter((row) => row.date === READ_DAY);
    expect(plain.length).toBeGreaterThan(0);
    expect(plain.every((row) => row.reads === READS)).toBe(true);

    // The M24 day carries the block, so the money follows `paid.reads` and not
    // the free reads beside it: nobody was billed for those, so nobody earned
    // anything from them.
    const paid = shares.filter((row) => row.date === PAID_DAY);
    expect(paid.length).toBe(plain.length);
    expect(paid.every((row) => row.reads === PAID_DAY_PAID)).toBe(true);
    expect(paid.some((row) => row.reads === PAID_DAY_READS)).toBe(false);

    // And the reconciliation of each day closes over the same half it priced.
    const closes = rows.filter((row) => row.kind === "reconciliation");
    expect(
      closes.map((row) => [row.date, row.reads, row.ref["ok"]]),
    ).toEqual([
      [PAID_DAY, PAID_DAY_PAID, true],
      [READ_DAY, READS, true],
    ]);

    const stake = rows.find((row) => row.kind === "dispute_stake")!;
    expect(stake.unit).toBe("standing");
    expect(stake.entry_id).toBe(VERIFIED_ENTRY_ID);
    expect(stake.id).toBe(`dispute_stake:${stake.seq}`);

    // No payout is ever derivable, so none is ever written. Nor the legacy
    // `revalidation_reward`: D-095 pays a changed check in standing, the
    // currency its stake was in, so the kind is no longer a `StakeKind` and
    // this fold cannot produce one — which is why the storage readers skip a
    // row an older log may still hold, rather than showing what no clone can
    // recompute.
    expect(kinds).not.toContain("payout");
    expect(kinds).not.toContain("revalidation_reward");
  });

  it("counts all three families in the manifest", () => {
    const manifest = jsonOf(files, "mirror.json") as Record<string, unknown>;
    expect(manifest["attestations"]).toBe(1);
    expect(manifest["standing_position"]).toBe(head);
    expect(manifest["ledger_rows"]).toBe(
      linesOf(files, "ledger.jsonl").length,
    );
    expect(manifest["ledger_rows"]).toBe(
      mirrorLedgerRows(richEvents, richSeals[1]!.sealed_at).length,
    );
  });

  it("builds the same bytes twice with all three families in it", () => {
    expect(buildMirror(richInput())).toEqual(files);
  });
});

/**
 * The reward an upheld dispute is paid, recomputed from the same events the
 * sweep's ledger step prices it from.
 *
 * Whitepaper Section 6: an upheld challenge "returns the stake, pays the
 * challenger, overturns the entry, and claws back what the approvers earned on
 * it (Section 9)" — one sentence, and the last clause is the amount of the
 * second. So the reward is a function of the log like every other row in the
 * fold, and this is the property that makes verify-mirror's ledger check worth
 * running: a clone recomputes the amount rather than believing it.
 */
describe("the ledger fold over an upheld dispute", () => {
  const DAY = "2026-09-09";
  const READS = 4_000;

  /** The log with a day of reads before the overturn: money still in holdback. */
  let withShares: Event[] = [];
  /** The same overturn with no day of reads at all: nothing was ever held. */
  let withoutShares: Event[] = [];

  function rowsOf(events: readonly Event[]): LedgerRow[] {
    return mirrorLedgerRows(events, "2026-09-12T00:00:00.000Z");
  }

  function upheld(events: readonly Event[], at: string): Promise<Event[]> {
    return appendEvent(events, {
      at,
      type: "dispute_upheld",
      entry_id: VERIFIED_ENTRY_ID,
      payload: { correction_entry_id: CORRECTION_ENTRY_ID },
    });
  }

  beforeAll(async () => {
    const one = await buildVerifyWorld({ withDispute: "outsider" });
    withoutShares = await upheld(one.bundle.events, "2026-09-10T12:00:00.000Z");

    const day = await appendEvent(one.bundle.events, {
      at: "2026-09-10T00:20:00.000Z",
      type: "read_count",
      entry_id: null,
      payload: {
        date: DAY,
        reads: [{ entry_id: VERIFIED_ENTRY_ID, count: READS }],
        total: READS,
        counter_first: 1,
        counter_last: READS,
      },
    });
    withShares = await upheld(day, "2026-09-10T12:00:00.000Z");
  }, 120_000);

  it("prices the reward at what the entry's signers lost", () => {
    const rows = rowsOf(withShares);
    const clawbacks = rows.filter((row) => row.kind === "clawback");
    expect(clawbacks.length).toBeGreaterThan(0);

    const reward = rows.find((row) => row.kind === "dispute_reward")!;
    expect(reward.unit).toBe("micros");
    expect(reward.amount).toBe(
      -clawbacks.reduce((sum, row) => sum + row.amount, 0),
    );
    expect(reward.amount).toBeGreaterThan(0);
    // It leaves when the last clawed-back share would have.
    expect(reward.available_at).toBe(
      clawbacks.map((row) => row.available_at).sort().at(-1),
    );
    // The row the dispute door wrote, at the position it became owed, with the
    // record it was written as and the rows the price was read off under ref.
    const outcome = withShares.find((event) => event.type === "dispute_upheld")!;
    expect([reward.id, reward.seq, reward.at]).toEqual([
      `dispute_reward:${outcome.seq}`,
      outcome.seq,
      outcome.at,
    ]);
    expect(reward.ref).toMatchObject({
      operator: CHALLENGER_OPERATOR,
      amount: null,
      clawbacks: clawbacks.map((row) => row.id),
    });
    expect(reward.operator).toBe(CHALLENGER_OPERATOR);

    // And the refund beside it is untouched: the stake back, in standing.
    const refund = rows.find((row) => row.kind === "dispute_refund")!;
    expect([refund.unit, refund.seq]).toEqual(["standing", outcome.seq]);
  });

  it("prices it at zero when the entry had accrued nothing", () => {
    const rows = rowsOf(withoutShares);
    expect(rows.filter((row) => row.kind === "clawback")).toEqual([]);
    const reward = rows.find((row) => row.kind === "dispute_reward")!;
    expect([reward.unit, reward.amount, reward.available_at]).toEqual([
      "micros",
      0,
      null,
    ]);
  });

  it("recomputes the same row twice from the same events", () => {
    // The property verify-mirror's ledger check rests on: the fold is a
    // function, so a clone and the ledger it is a copy of cannot disagree.
    expect(rowsOf(withShares)).toEqual(rowsOf(withShares));
  });
});

/**
 * A day is priced at its own position in the log, never at the head (M24b).
 *
 * The sweep prices a published day in the run that published it, so the entry
 * it reads is the entry the log derives at that `read_count` — and a slot
 * rotation that lands afterwards belongs to the days after it. Rederiving every
 * day at the export's `asOf` would hand a verifier holders the entry did not
 * have on the day they were paid for, and the mirror's rows would disagree with
 * the ledger's on the same events.
 *
 * So: a verified entry read on one day, then reconfirmed by an operator that
 * held no slot, then read again on the next. Two days, one entry, two different
 * sets of holders.
 */
describe("the ledger fold across a slot rotation", () => {
  const DAY_ONE = "2026-09-09";
  const DAY_TWO = "2026-09-10";
  const READS = 1_000;

  /** The whole log: both days, with the rotation between them. */
  let rotated: Event[];
  /** The same log cut off after day one, which is all the sweep had then. */
  let throughDayOne: Event[];
  /** The operator the reconfirmation seats, which held no slot before it. */
  let newcomer = "";
  /** The operators the two approvals seated, in slot order. */
  let seated: string[] = [];

  function shares(events: readonly Event[], date: string): LedgerRow[] {
    return mirrorLedgerRows(events, "2026-09-11T00:00:00.000Z").filter(
      (row) => row.kind === "read_share" && row.date === date,
    );
  }

  function validators(rows: readonly LedgerRow[]): string[] {
    return rows
      .filter((row) => row.role === "validator")
      .map((row) => row.operator as string)
      .sort();
  }

  function readCount(date: string, at: string): Parameters<typeof appendEvent>[1] {
    return {
      at,
      type: "read_count",
      entry_id: null,
      payload: {
        date,
        reads: [{ entry_id: VERIFIED_ENTRY_ID, count: READS }],
        total: READS,
        counter_first: 1,
        counter_last: READS,
        paid: {
          reads: [{ entry_id: VERIFIED_ENTRY_ID, count: READS }],
          total: READS,
          keys: { key_0123456789abcdef: READS },
        },
        duplicates: [],
      },
    };
  }

  beforeAll(async () => {
    const world = await buildVerifyWorld();
    seated = [OUTSIDE_OPERATORS[0]!, OUTSIDE_OPERATORS[1]!].sort();
    newcomer = OUTSIDE_OPERATORS[2]!;

    const agent = Object.entries(world.bundle.registry.agents).find(
      ([, operator]) => operator === newcomer,
    )![0];

    // Day one, published the morning after it: the entry still holds exactly
    // the slots its two approvals seated.
    throughDayOne = await appendEvent(
      world.bundle.events,
      readCount(DAY_ONE, "2026-09-10T00:20:00.000Z"),
    );

    // The rotation: a trusted operator that signed nothing of this entry's
    // reconfirms it, and takes a slot for doing so.
    const record = {
      agent,
      operator: newcomer,
      snapshot_hash: world.entry["snapshot_hash"] as string,
      reproduction: null,
      observation: null,
      signed_at: "2026-09-10T12:00:00.000Z",
    };
    rotated = await appendEvent(throughDayOne, {
      at: "2026-09-10T12:00:00.000Z",
      type: "reconfirmation",
      entry_id: VERIFIED_ENTRY_ID,
      payload: {
        record,
        signature: await signRecord(
          VERIFIED_ENTRY_ID,
          "reconfirmation",
          record,
          world.keys[agent]!.privateKey,
        ),
      },
    });

    rotated = await appendEvent(
      rotated,
      readCount(DAY_TWO, "2026-09-11T00:20:00.000Z"),
    );
  }, 120_000);

  it("pays the first day the holders it had on the first day", () => {
    const rows = shares(rotated, DAY_ONE);
    expect(rows.length).toBeGreaterThan(0);
    expect(validators(rows)).toEqual(seated);
    expect(validators(rows)).not.toContain(newcomer);
    expect(rows.every((row) => row.reads === READS)).toBe(true);
  });

  it("pays the second day the holder the rotation seated", () => {
    const rows = shares(rotated, DAY_TWO);
    expect(validators(rows)).toEqual([...seated, newcomer].sort());
    expect(rows.every((row) => row.reads === READS)).toBe(true);
  });

  it("leaves the first day's rows exactly what they were before the log grew", () => {
    // The equality that makes the mirror a recomputation of the ledger rather
    // than a second opinion: what the sweep stored for a day is what this fold
    // says for it, on a log that has since moved on.
    expect(shares(rotated, DAY_ONE)).toEqual(shares(throughDayOne, DAY_ONE));
  });
});

/**
 * The bounded bundle (decision D-120): one entry's seals instead of the whole
 * log, read as narrowly as it is written.
 *
 * `npm run export -- ... --bounded` writes the same two files with a smaller
 * second one: the event the entry's seal names, a Merkle path from it to the
 * root that seal committed to, that seal and the seal before it, the registry
 * and the captures. Every test here is the same story the full verifier's tests
 * tell — build a real world, hand the verifier both files, then edit exactly one
 * thing and watch it named — with two more asked of it: that the narrower file
 * still proves what it claims and says which checks it cannot make, and that
 * building it does not walk the log.
 *
 * The log is served to the exporter over a fake of the Worker's read routes
 * rather than over a Worker, because what is being pinned is the requests the
 * command makes and the bundle it builds out of the answers. The proofs the fake
 * serves are real Merkle paths over the seal's real leaves, computed by
 * src/merkle.ts, exactly as `GET /events/{seq}/proof` computes them.
 */

import { describe, expect, it } from "vitest";

import {
  appendEvent,
  base64Decode,
  buildSeal,
  deriveEntry,
  sealHash,
  sealsForEntries,
  type Entry,
  type Event,
  type Seal,
} from "../src/index.js";
import type { Sidecar } from "../src/derive.js";
import { withholdEntry } from "../src/release.js";
import { buildExport, exportPlan } from "../src/cli/export.js";
import type { HttpClient } from "../src/cli/validator.js";
import { decodeProof, encodeProof, inclusionProof } from "../src/merkle.js";
import { LIST_PAGE_LIMIT } from "../src/policy.js";
import { verifyOffline, type LogBundle, type VerifyReport } from "../src/verify.js";
import { buildVerifyWorld, type VerifyWorld } from "./helpers/verify-world.js";

const ORIGIN = "https://bounded.test";
const NOW = new Date("2026-05-01T00:00:00.000Z");

/** How many filler events the size and cost tests put between the entry and the head. */
const FILLER_EVENTS = 400;

type Json = Record<string, unknown>;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** The seal covering one event seq in this log, or null. */
function covering(seals: readonly Seal[], seq: number): Seal | null {
  for (const seal of seals) {
    if (seq >= seal.first_seq && seq <= seal.last_seq) return seal;
  }
  return null;
}

/**
 * The Worker's read routes, over a log held in memory, recording every path it
 * is asked for.
 *
 * Only the routes the export actually reads, and each one answering the shape
 * the real route answers: a page of events with the head beside it, a page of
 * seals, one seal by seq, one event's inclusion proof, the operator list and
 * each operator's own page, and the captures. `asked` is what the cost test
 * counts.
 */
function logHttp(
  bundle: LogBundle,
  entry: unknown,
): HttpClient & { asked: string[] } {
  const ordered = [...bundle.events].sort((left, right) => left.seq - right.seq);
  const head = ordered.length === 0 ? null : ordered[ordered.length - 1]!.seq;
  const asked: string[] = [];

  return {
    asked,
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      const path = url.pathname;
      asked.push(`${path}${url.search}`);
      const limit = Number(url.searchParams.get("limit") ?? LIST_PAGE_LIMIT);
      const after = url.searchParams.get("after");

      const entryEvents = path.match(/^\/entries\/([^/]+)\/events$/);
      if (entryEvents !== null) {
        const id = decodeURIComponent(entryEvents[1]!);
        const own = ordered.filter((event) => event.entry_id === id);
        const proofs = [];
        for (const event of own) {
          const seal = covering(bundle.seals, event.seq);
          if (seal === null) continue;
          const leaves = ordered
            .filter(
              (leaf) => leaf.seq >= seal.first_seq && leaf.seq <= seal.last_seq,
            )
            .map((leaf) => leaf.hash);
          proofs.push({
            seq: event.seq,
            hash: event.hash,
            seal: {
              seq: seal.seq,
              root: seal.root,
              hash: seal.hash,
              sealed_at: seal.sealed_at,
            },
            inclusion_proof: encodeProof(
              await inclusionProof(leaves, event.seq - seal.first_seq),
            ),
            witnesses: seal.witnesses,
          });
        }
        return json({ entry_id: id, head, events: own, proofs });
      }
      if (path.startsWith("/entries/")) return json(entry);

      if (path === "/events") {
        const from = after === null ? 0 : Number(after) + 1;
        const page = ordered.filter((event) => event.seq >= from).slice(0, limit);
        return json({ events: page, head });
      }

      if (path === "/seals") {
        const from = after === null ? 0 : Number(after) + 1;
        const sorted = [...bundle.seals].sort((left, right) => left.seq - right.seq);
        const page = sorted.filter((seal) => seal.seq >= from).slice(0, limit);
        const sealHead = sorted.length === 0 ? null : sorted[sorted.length - 1]!.seq;
        return json({ seals: page, head: sealHead });
      }

      const sealSeq = path.match(/^\/seals\/(\d+)$/);
      if (sealSeq !== null) {
        const found = bundle.seals.find((seal) => seal.seq === Number(sealSeq[1]));
        return found === undefined ? json({ error: "not_found" }, 404) : json(found);
      }

      const proofSeq = path.match(/^\/events\/(\d+)\/proof$/);
      if (proofSeq !== null) {
        const seq = Number(proofSeq[1]);
        const event = ordered.find((candidate) => candidate.seq === seq);
        if (event === undefined) return json({ error: "not_found" }, 404);
        const seal = covering(bundle.seals, seq);
        if (seal === null) return json({ error: "unsealed" }, 404);
        const leaves = ordered
          .filter((leaf) => leaf.seq >= seal.first_seq && leaf.seq <= seal.last_seq)
          .map((leaf) => leaf.hash);
        const built = await inclusionProof(leaves, seq - seal.first_seq);
        return json({
          seq,
          hash: event.hash,
          seal: {
            seq: seal.seq,
            root: seal.root,
            hash: seal.hash,
            sealed_at: seal.sealed_at,
          },
          inclusion_proof: encodeProof(built),
          witnesses: seal.witnesses,
        });
      }

      if (path === "/operators") {
        return json({
          operators: Object.keys(bundle.registry.operators).map((id) => ({ id })),
        });
      }
      if (path.startsWith("/operators/")) {
        const id = decodeURIComponent(path.slice("/operators/".length));
        const known = bundle.registry.operators[id];
        if (known === undefined) return json({ error: "not_found" }, 404);
        return json({
          id,
          maintainer: known.maintainer,
          provider: known.provider,
          domains: known.domains ?? [],
          agents: Object.entries(bundle.registry.agents)
            .filter(([, operator]) => operator === id)
            .map(([agent]) => agent),
        });
      }

      // The sidecar is absent here, so the capture's own response header is the
      // content type the export records — the fallback the real reader takes.
      if (path.endsWith("/sidecar")) return json({ error: "not_found" }, 404);
      if (path.startsWith("/captures/")) {
        const hash = decodeURIComponent(path.slice("/captures/".length));
        const capture = bundle.captures[hash];
        if (capture === undefined) return json({ error: "not_found" }, 404);
        const bytes = base64Decode(capture.body_base64);
        // The bytes as their own buffer: a view over a shared one is not a body
        // the platform's Response takes.
        const body = bytes.buffer.slice(
          bytes.byteOffset,
          bytes.byteOffset + bytes.byteLength,
        ) as ArrayBuffer;
        return new Response(body, {
          status: 200,
          headers: {
            "content-type": capture.content_type ?? "application/octet-stream",
          },
        });
      }

      return json({ error: "not_found" }, 404);
    },
  };
}

/**
 * A world whose log runs on past the entry, sealed twice.
 *
 * Two seals on purpose, and the split is before the submission: the entry's own
 * event is under seal 1, so a bounded bundle has to carry seal 0 as well — and,
 * because seal 1 names seal 0's hash, the link between them is a thing the
 * verifier can check rather than a claim it has to take. `filler` events after
 * the decisions put the head a long way past the entry, which is what the cost
 * and size tests are about.
 *
 * The entry is re-derived over these seals rather than reused, because its own
 * `seal` object is the inclusion proof of its submission within the batch that
 * sealed it, and resealing the log moves that batch.
 */
async function world(filler: number): Promise<{
  world: VerifyWorld;
  entry: Entry;
  bundle: LogBundle;
}> {
  const built = await buildVerifyWorld();
  let events: Event[] = [...built.bundle.events];
  const last = events[events.length - 1]!;
  for (let index = 0; index < filler; index += 1) {
    events = await appendEvent(events, {
      at: last.at,
      type: "pool_snapshot",
      entry_id: null,
      payload: { operators: Object.values(built.bundle.registry.agents) },
    });
  }

  const submission = events.find(
    (event) => event.type === "entry_submitted" && event.entry_id === built.entryId,
  )!;
  const first = await buildSeal(events.slice(0, submission.seq), null, {
    now: built.bundle.as_of,
  });
  if (!first.ok) throw new Error(`world: buildSeal ${first.reason}`);
  const second = await buildSeal(events, first.seal, { now: built.bundle.as_of });
  if (!second.ok) throw new Error(`world: buildSeal ${second.reason}`);
  const seals = [first.seal, second.seal];

  const entry = deriveEntry(
    events,
    built.entryId,
    { now: built.bundle.as_of },
    await sealsForEntries(events, seals),
  ).entry;

  return { world: built, entry, bundle: { ...built.bundle, events, seals } };
}

/** The two files, bounded or whole, out of the command itself. */
async function exported(
  bundle: LogBundle,
  entry: unknown,
  bounded: boolean,
): Promise<{ entry: unknown; bundle: LogBundle; asked: string[] }> {
  const http = logHttp(bundle, entry);
  const result = await buildExport({
    baseUrl: ORIGIN,
    entryId: (entry as Json)["id"] as string,
    http,
    now: NOW,
    bounded,
  });
  return { entry: result.entry, bundle: result.bundle, asked: http.asked };
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

/** One world per file, built once: the tests copy the files and edit their copy. */
let cached: Awaited<ReturnType<typeof world>> | null = null;
async function small(): Promise<Awaited<ReturnType<typeof world>>> {
  if (cached === null) cached = await world(0);
  return cached;
}

describe("a bounded export of a verified entry", () => {
  it("verifies ok, and says which checks it could not make", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, true);

    expect(files.bundle.bounded).toBe(true);
    const report = await verifyOffline(files.entry, files.bundle);
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.entry_id).toBe(built.world.entryId);
    // The whole point of the marker: an `ok` here is a narrower sentence than
    // an `ok` over the whole log, and the report says so rather than leaving a
    // reader to infer it.
    expect(report.bounded).toBe(true);
    expect(report.not_run).toEqual([
      "chain",
      "exclusions",
      "derived",
      "attestations",
    ]);
  }, 120_000);

  it("carries this entry's own events, a proof each, and both seals", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, true);

    // Every event in the file belongs to this entry — its submission and its
    // decisions, which is what the record signatures are checked on — and the
    // file is a fraction of the log it came out of.
    const own = built.bundle.events.filter(
      (event) => event.entry_id === built.world.entryId,
    );
    expect(files.bundle.events.map((event) => event.seq)).toEqual(
      own.map((event) => event.seq),
    );
    expect(files.bundle.events.length).toBeGreaterThan(1);
    expect(files.bundle.events.length).toBeLessThan(built.bundle.events.length);

    // One proof per event, each against a seal the bundle carries, with the
    // seal before each of those beside it so the links can be checked.
    for (const event of files.bundle.events) {
      const proof = files.bundle.proofs?.[String(event.seq)];
      expect(proof).toBeDefined();
      expect(
        files.bundle.seals.some((seal) => seal.seq === proof!.seal_seq),
      ).toBe(true);
    }
    expect(files.bundle.seals.map((seal) => seal.seq).sort()).toEqual([0, 1]);
    expect(files.bundle.head).toBe(
      Math.max(...built.bundle.events.map((event) => event.seq)),
    );
  }, 120_000);

  it("still verifies the full bundle exactly as it always did", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, false);

    expect(files.bundle.bounded).toBeUndefined();
    expect(files.bundle.proofs).toBeUndefined();
    const report = await verifyOffline(files.entry, files.bundle);
    expect(report.diffs).toEqual([]);
    expect(report.bounded).toBe(false);
    expect(report.not_run).toEqual([]);
  }, 120_000);

  it("checks every record signature, which is what the events are there for", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, true);
    const edited = clone(files.bundle);

    // One validator's record, changed after it was signed. A bounded bundle
    // carries the decision's own event, so this is caught here exactly as it is
    // on a full bundle — which is why `records` is not among the checks a
    // bounded bundle names as not run.
    const decision = edited.events.find((event) => event.type === "validation")!;
    ((decision.payload as Json)["record"] as Json)["reason"] = "something else";

    const report = await verifyOffline(files.entry, edited);
    expect(
      report.diffs.some(
        (diff) =>
          diff.check === "records" &&
          diff.field === `/events/${decision.seq}` &&
          diff.reason === "bad_signature",
      ),
    ).toBe(true);
  }, 120_000);
});

describe("what a bounded export costs on the wire", () => {
  it("never walks the log, and asks the same questions however long it is", async () => {
    const short = await small();
    const long = await world(FILLER_EVENTS);
    expect(long.bundle.events.length).toBeGreaterThan(FILLER_EVENTS);

    const near = await exported(short.bundle, short.entry, true);
    const far = await exported(long.bundle, long.entry, true);

    // Not one page of the log: the entry's own door answers its events and
    // their proofs in a single call.
    for (const asked of [near.asked, far.asked]) {
      expect(asked.filter((path) => path.startsWith("/events?"))).toHaveLength(0);
      expect(
        asked.filter((path) => /^\/entries\/[^/]+\/events$/.test(path)),
      ).toHaveLength(1);
    }

    // The log grew by four hundred events and the export asked exactly the same
    // questions: the entry, its own events with their proofs, two seals, the
    // registry and the captures. That is the bound, and it is a bound on the
    // reads and not only on the file.
    expect(far.asked.length).toBe(near.asked.length);

    // The whole log, for contrast: the walk that the bound exists to avoid.
    const full = await exported(long.bundle, long.entry, false);
    expect(
      full.asked.filter((path) => path.startsWith("/events?")).length,
    ).toBeGreaterThan(1);
    expect(full.asked.length).toBeGreaterThan(far.asked.length);
  }, 600_000);

  it("is a small fraction of the whole log on a log of a few hundred events", async () => {
    const big = await world(FILLER_EVENTS);
    const full = await exported(big.bundle, big.entry, false);
    const bounded = await exported(big.bundle, big.entry, true);

    const size = (value: unknown): number =>
      new TextEncoder().encode(JSON.stringify(value, null, 2)).length;
    const ratio = size(bounded.bundle) / size(full.bundle);

    // A ratio and not a byte count: what is pinned is that the bundle stops
    // growing with the log, not any particular size of any particular world.
    // The bar is a tenth because the captures and the registry are in both
    // files and do not shrink, so a smaller world would not reach what this one
    // measures and the pin would be a pin on the world rather than on the bound.
    expect(ratio).toBeLessThan(0.1);

    // And it still proves what it claims at that size.
    const report: VerifyReport = await verifyOffline(bounded.entry, bounded.bundle);
    expect(report.diffs).toEqual([]);
    expect(report.bounded).toBe(true);
  }, 600_000);
});

describe("a bounded bundle somebody edited", () => {
  it("names the event whose hash no longer recomputes", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, true);
    const edited = clone(files.bundle);

    // The sealed core, changed. The hash it is carried under is now a hash of
    // something else, so the event fails before its proof is reached.
    const target = edited.events.find(
      (event) => event.type === "entry_submitted",
    )!;
    ((target.payload as Json)["core"] as Json)["claim"] = "something else";

    const report = await verifyOffline(files.entry, edited);
    expect(report.ok).toBe(false);
    expect(
      report.diffs.some(
        (diff) =>
          diff.check === "proof" &&
          diff.field === `/events/${target.seq}` &&
          diff.reason === "bad_hash",
      ),
    ).toBe(true);
  }, 120_000);

  it("names the proof that does not reach the root", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, true);
    const edited = clone(files.bundle);

    // The event untouched and one sibling of its path replaced: the proof is
    // still exactly the shape a proof is, the hash still recomputes, and the
    // path no longer reaches the root the seal committed to.
    const seq = edited.events[0]!.seq;
    const decoded = decodeProof(edited.proofs![String(seq)]!.inclusion_proof)!;
    expect(decoded.path.length).toBeGreaterThan(0);
    edited.proofs![String(seq)] = {
      ...edited.proofs![String(seq)]!,
      inclusion_proof: encodeProof({
        ...decoded,
        path: [`sha256:${"0".repeat(64)}`, ...decoded.path.slice(1)],
      }),
    };

    const report = await verifyOffline(files.entry, edited);
    expect(
      report.diffs.some(
        (diff) =>
          diff.check === "proof" &&
          diff.field === `/events/${seq}` &&
          diff.reason === "bad_proof",
      ),
    ).toBe(true);
  }, 120_000);

  it("names the seal a proof is against when the bundle no longer carries it", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, true);
    const edited = clone(files.bundle);

    edited.seals = edited.seals.filter((seal) => seal.seq !== 1);

    const report = await verifyOffline(files.entry, edited);
    expect(report.ok).toBe(false);
    expect(
      report.diffs.some(
        (diff) => diff.check === "proof" && diff.reason === "seal_missing",
      ),
    ).toBe(true);
  }, 120_000);

  it("names the seal before it when that one is missing", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, true);
    const edited = clone(files.bundle);

    // Seal 0 dropped. Seal 1 covers the entry's event, so the link it is
    // checked by is one the bundle was supposed to bring and did not.
    edited.seals = edited.seals.filter((seal) => seal.seq !== 0);

    const report = await verifyOffline(files.entry, edited);
    expect(report.ok).toBe(false);
    expect(
      report.diffs.some(
        (diff) =>
          diff.check === "seals" &&
          diff.field === "/seals/1" &&
          diff.reason === "seal_missing",
      ),
    ).toBe(true);
  }, 120_000);

  it("names a seal chained onto the wrong one", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, true);
    const edited = clone(files.bundle);

    // Seal 1 relinked to a seal 0 that is not the one beside it, and its own
    // hash recomputed over the new link so that the hash check passes. That is
    // the forgery worth catching: a hand-edited prev_hash alone fails the seal's
    // own hash and never reaches the link, so a test that only edits the field
    // pins the hash check twice and the link check not at all. Here the seal is
    // internally consistent and the only thing wrong with it is that the seal
    // beside it is not the seal it names.
    const second = edited.seals.find((seal) => seal.seq === 1)!;
    second.prev_hash = `sha256:${"0".repeat(64)}`;
    const { hash: _hash, witnesses: _witnesses, registry: _registry, ...fields } =
      second;
    second.hash = await sealHash(fields);

    const report = await verifyOffline(files.entry, edited);
    const named = report.diffs.filter(
      (diff) => diff.check === "seals" && diff.field === "/seals/1",
    );
    expect(named.map((diff) => diff.reason)).toEqual(["bad_seal_link"]);
    expect(named[0]!.expected).toBe(
      edited.seals.find((seal) => seal.seq === 0)!.hash,
    );
  }, 120_000);

  it("names a proof pointed at a seal that does not cover it", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, true);
    const edited = clone(files.bundle);

    // The proof moved onto the seal before the one that covers the event. The
    // seal is in the bundle, so this is not a missing seal; it simply does not
    // cover this seq, which is a different thing to tell a reader and is caught
    // before the path is ever checked against a root it was never built for.
    const seq = edited.events[0]!.seq;
    edited.proofs![String(seq)] = {
      ...edited.proofs![String(seq)]!,
      seal_seq: 0,
    };

    const report = await verifyOffline(files.entry, edited);
    expect(report.ok).toBe(false);
    expect(
      report.diffs.some(
        (diff) =>
          diff.check === "proof" &&
          diff.field === `/events/${seq}` &&
          diff.reason === "wrong_seal",
      ),
    ).toBe(true);
  }, 120_000);
});

describe("a bounded export inside the release window", () => {
  it("answers entry_withheld, exactly as the full one does", async () => {
    const built = await small();
    const files = await exported(built.bundle, built.entry, true);

    // The entry file `npm run export` writes for a reader with no entitlement,
    // built out of src/release.ts's own function so nothing about its shape is
    // this test's invention. A bounded bundle changes nothing about the window:
    // the file is still not an entry to check but a promise that one exists, and
    // the honest answer is still the day it opens and nothing else.
    const held = await withholdEntry(built.entry, {} as unknown as Sidecar, "");

    const report = await verifyOffline(held.proof, files.bundle);
    expect(report.ok).toBe(false);
    expect(report.entry_id).toBe(built.world.entryId);
    expect(report.diffs.map((diff) => diff.reason)).toEqual(["entry_withheld"]);
    expect(report.diffs[0]!.check).toBe("window");
    // And the bounded marker is still on the report, because what the reader
    // holds is still a bounded bundle whatever the window did to the entry.
    expect(report.bounded).toBe(true);
    expect(report.not_run).toEqual([
      "chain",
      "exclusions",
      "derived",
      "attestations",
    ]);
  }, 120_000);
});

describe("the flag", () => {
  it("is off unless it is asked for, and takes no value", () => {
    const plain = exportPlan(["https://app.test", "nmk_0", "./out"]);
    expect(plain?.bounded).toBe(false);

    const asked = exportPlan(["https://app.test", "nmk_0", "./out", "--bounded"]);
    expect(asked?.bounded).toBe(true);

    // Beside a credential, in either order: the flag carries no value, so the
    // walk over the rest cannot be a walk in pairs.
    expect(
      exportPlan(["https://app.test", "nmk_0", "./out", "--bounded", "--key", "k"]),
    ).toEqual({
      baseUrl: "https://app.test",
      entryId: "nmk_0",
      outDir: "./out",
      key: "k",
      signPath: null,
      bounded: true,
    });
    expect(
      exportPlan(["https://app.test", "nmk_0", "./out", "--key", "k", "--bounded"])
        ?.bounded,
    ).toBe(true);
  });

  it("refuses what it has always refused", () => {
    // Twice is not louder, an unknown flag is still refused, and both
    // credentials at once is still a reader who has not said which they meant.
    expect(
      exportPlan(["https://app.test", "nmk_0", "./out", "--bounded", "--bounded"]),
    ).toBeNull();
    expect(exportPlan(["https://app.test", "nmk_0", "./out", "--small"])).toBeNull();
    expect(
      exportPlan(["https://app.test", "nmk_0", "./out", "--key", "k", "--sign", "f"]),
    ).toBeNull();
    expect(exportPlan(["https://app.test", "nmk_0", "./out", "--key"])).toBeNull();
  });
});

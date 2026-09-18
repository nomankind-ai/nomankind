/**
 * The reader kit's client, against recorded doors.
 *
 * Decision D-131 item 4 and decision D-127 item 4b are the two things these
 * tests are about: a reader holds no key, and every fact it is handed carries
 * who signed it. So the fake door below is served without ever looking at an
 * authorization header — there is none to look at — and every case asserts on
 * the attribution that came back beside the entry.
 *
 * The bundle and the entry are the committed verify fixtures, so `verify` here
 * is the same two files a stranger downloads and the same verdict they get.
 */

import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { attributionOf } from "../src/attribution.js";
import { base64Decode } from "../src/encoding.js";
import type { Event } from "../src/events.js";
import { runKit } from "../src/cli/kit.js";
import {
  createReader,
  KIT_NAME,
  ReaderRefusal,
  type KitFetch,
  type SyncItem,
} from "../src/kit/client.js";

const BASE = "https://app.nomankind.ai";
const FIXTURES = join(import.meta.dirname, "fixtures", "verify");

type Json = Record<string, unknown>;

async function fixture(name: string): Promise<Json> {
  return JSON.parse(await readFile(join(FIXTURES, name), "utf8")) as Json;
}

/** The entry, the bundle, and the attribution block the doors would answer. */
async function world(): Promise<{
  entry: Json;
  bundle: Json;
  attribution: Json;
  entryId: string;
}> {
  const entry = await fixture("verified-entry.json");
  const bundle = await fixture("log.json");
  const events = bundle["events"] as Event[];
  const attribution = attributionOf(
    entry as never,
    events,
    new Map(),
  ) as unknown as Json;
  return { entry, bundle, attribution, entryId: entry["id"] as string };
}

interface Recorded {
  /** Every path the door was asked for, in order. */
  readonly paths: string[];
  /** Every user-agent the door was sent. */
  readonly agents: string[];
}

/** A door built out of a routing table, plus what it was asked. */
function door(
  routes: (url: URL) => { status: number; body: unknown } | null,
): { fetch: KitFetch; seen: Recorded } {
  const seen: Recorded = { paths: [], agents: [] };
  const fetch: KitFetch = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    seen.paths.push(`${url.pathname}${url.search}`);
    seen.agents.push(request.headers.get("user-agent") ?? "");
    const answer = routes(url);
    if (answer === null) {
      return new Response(JSON.stringify({ error: "not_found" }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify(answer.body), {
      status: answer.status,
      headers: { "content-type": "application/json" },
    });
  };
  return { fetch, seen };
}

describe("the reader kit's client: one fact", () => {
  it("reads one fact by id, with its status, class and attribution", async () => {
    const { entry, attribution, entryId } = await world();
    const { fetch } = door((url) => {
      if (url.pathname === `/read/${entryId}`) {
        return {
          status: 200,
          body: {
            entry,
            sidecar: {
              effective_tier: "stated",
              verification_class: "registered",
            },
            seal: null,
            receipt: { entry_id: entryId, counter: 7 },
          },
        };
      }
      if (url.pathname === `/entries/${entryId}/attribution`) {
        return { status: 200, body: attribution };
      }
      return null;
    });

    const reader = createReader({ base: BASE, fetch });
    const answer = await reader.read(entryId);

    expect(answer.entry_id).toBe(entryId);
    expect(answer.status).toBe("verified");
    expect(answer.effective_tier).toBe("stated");
    expect(answer.verification_class).toBe("registered");
    expect(answer.receipted).toBe(true);
    expect(answer.attribution).not.toBeNull();
    expect(answer.citation).toBe(attribution["citation"]);
    expect(answer.citation).toContain(entryId);
  });

  it("names the kit in the user-agent of every request it makes", async () => {
    const { entry, attribution, entryId } = await world();
    const { fetch, seen } = door((url) =>
      url.pathname === `/read/${entryId}`
        ? { status: 200, body: { entry, sidecar: null } }
        : { status: 200, body: attribution },
    );
    await createReader({ base: BASE, fetch }).read(entryId);
    expect(seen.agents.length).toBeGreaterThan(1);
    for (const agent of seen.agents) expect(agent).toContain(KIT_NAME);
  });

  it("lets a caller name its own user-agent", async () => {
    const { entry, attribution, entryId } = await world();
    const { fetch, seen } = door((url) =>
      url.pathname === `/read/${entryId}`
        ? { status: 200, body: { entry, sidecar: null } }
        : { status: 200, body: attribution },
    );
    await createReader({ base: BASE, fetch, userAgent: "my-agent/2" }).read(
      entryId,
    );
    expect(seen.agents[0]).toBe("my-agent/2");
  });

  it("falls back to the entry door when the frozen reader says not verified", async () => {
    const draft = await fixture("draft-entry.json");
    const entryId = draft["id"] as string;
    const { fetch, seen } = door((url) => {
      if (url.pathname === `/read/${entryId}`) {
        return {
          status: 409,
          body: { error: "entry_not_verified", status: "draft" },
        };
      }
      if (url.pathname === `/entries/${entryId}`) {
        return { status: 200, body: draft };
      }
      return { status: 404, body: { error: "not_found" } };
    });

    const answer = await createReader({ base: BASE, fetch }).read(entryId);
    expect(answer.status).toBe("draft");
    expect(answer.receipted).toBe(false);
    expect(answer.verification_class).toBeNull();
    // A draft has no attribution door answer here, and that is not a failure.
    expect(answer.attribution).toBeNull();
    expect(seen.paths).toContain(`/entries/${entryId}`);
  });

  it("raises a refusal that is not the not-verified one, without trying the entry door", async () => {
    // The entry door answers here, and would answer a fallback: if the client
    // fell back on any 4xx rather than on 409 alone, this test would pass on
    // the entry and never notice. So the assertion is on what was asked —
    // `/read/{id}` and nothing after it — as well as on what came back.
    const draft = await fixture("draft-entry.json");
    const { fetch, seen } = door((url) =>
      url.pathname === `/entries/${draft["id"] as string}`
        ? { status: 200, body: draft }
        : { status: 429, body: { error: "rate_limited" } },
    );
    const reader = createReader({ base: BASE, fetch });
    const entryId = draft["id"] as string;

    const error = await reader.read(entryId).then(
      () => null,
      (raised: unknown) => raised,
    );
    expect(error).toBeInstanceOf(ReaderRefusal);
    const refusal = error as ReaderRefusal;
    expect(refusal.status).toBe(429);
    expect(refusal.reason).toBe("rate_limited");
    expect(refusal.path).toBe(`/read/${entryId}`);
    expect(seen.paths).toEqual([`/read/${entryId}`]);
    expect(seen.paths.some((path) => path.startsWith("/entries/"))).toBe(false);
  });

  it("falls back on 409 and on nothing else", async () => {
    const draft = await fixture("draft-entry.json");
    const entryId = draft["id"] as string;
    for (const status of [400, 403, 404, 410, 429, 500, 503]) {
      const { seen, fetch } = door((url) =>
        url.pathname === `/entries/${entryId}`
          ? { status: 200, body: draft }
          : { status, body: { error: "refused" } },
      );
      const raised = await createReader({ base: BASE, fetch })
        .read(entryId)
        .then(
          () => null,
          (error: unknown) => error,
        );
      expect(raised, `status ${status} must not fall back`).toBeInstanceOf(
        ReaderRefusal,
      );
      expect(seen.paths).toEqual([`/read/${entryId}`]);
    }
  });

  it("reads by subject and category, passing every filter as a parameter", async () => {
    const { entry, attribution, entryId } = await world();
    const { fetch, seen } = door((url) => {
      if (url.pathname === "/read") {
        return { status: 200, body: { entry, sidecar: { effective_tier: "stated", verification_class: "mixed" } } };
      }
      return { status: 200, body: attribution };
    });

    const answer = await createReader({ base: BASE, fetch }).read({
      subject: "openai/gpt-5",
      category: "pricing",
      domain: "ai-ecosystem",
      min_tier: "stated",
      min_class: "mixed",
      max_age: 90,
    });

    const asked = new URL(seen.paths[0]!, BASE).searchParams;
    expect(asked.get("subject")).toBe("openai/gpt-5");
    expect(asked.get("category")).toBe("pricing");
    expect(asked.get("domain")).toBe("ai-ecosystem");
    expect(asked.get("min_tier")).toBe("stated");
    expect(asked.get("min_class")).toBe("mixed");
    expect(asked.get("max_age")).toBe("90");
    expect(answer.verification_class).toBe("mixed");
    expect(answer.entry_id).toBe(entryId);
  });
});

describe("the reader kit's client: the delta stream", () => {
  /** Two pages and then a door with nothing more to say. */
  function stream(entry: Json, attribution: Json): (url: URL) => {
    status: number;
    body: unknown;
  } | null {
    return (url: URL) => {
      if (url.pathname !== "/sync") return null;
      const from = Number(url.searchParams.get("from"));
      if (from === 0) {
        return {
          status: 200,
          body: {
            from: 0,
            head: 2,
            sealed_head: 2,
            events: [
              {
                seq: 1,
                kind: "entry",
                event: { seq: 1, type: "submission", entry_id: entry["id"] },
                entry,
                sidecar: {
                  effective_tier: "stated",
                  verification_class: "registered",
                },
                attribution,
              },
              {
                seq: 2,
                kind: "registry",
                event: { seq: 2, type: "operator_registered", entry_id: null },
                entry: null,
                sidecar: null,
                attribution: null,
              },
            ],
          },
        };
      }
      if (from === 2) {
        return {
          status: 200,
          body: {
            from: 2,
            head: 3,
            events: [
              {
                seq: 3,
                kind: "entry",
                event: { seq: 3, type: "validation", entry_id: entry["id"] },
                entry,
                sidecar: {
                  effective_tier: "stated",
                  verification_class: "community",
                },
                attribution,
              },
            ],
          },
        };
      }
      return { status: 200, body: { from, head: null, events: [] } };
    };
  }

  it("pages the free door until the head stops advancing", async () => {
    const { entry, attribution } = await world();
    const { fetch, seen } = door(stream(entry, attribution));
    const items: SyncItem[] = [];
    for await (const item of createReader({ base: BASE, fetch }).sync({
      from: 0,
      limit: 2,
    })) {
      items.push(item);
    }

    expect(items.map((item) => item.seq)).toEqual([1, 2, 3]);
    // Three pages: two with events and the empty one that ended the walk.
    expect(seen.paths).toHaveLength(3);
    expect(seen.paths[0]).toContain("from=0");
    expect(seen.paths[1]).toContain("from=2");
  });

  it("carries the verification class and the attribution on every entry item", async () => {
    const { entry, attribution } = await world();
    const { fetch } = door(stream(entry, attribution));
    const items: SyncItem[] = [];
    for await (const item of createReader({ base: BASE, fetch }).sync({
      from: 0,
      limit: 2,
    })) {
      items.push(item);
    }

    const [first, registry, third] = items;
    expect(first!.verification_class).toBe("registered");
    expect(first!.attribution).not.toBeNull();
    expect(first!.citation).toBe(attribution["citation"]);
    expect(third!.verification_class).toBe("community");
    // An item about no entry carries no state and no block, which is the truth
    // about a registry event rather than a gap.
    expect(registry!.entry).toBeNull();
    expect(registry!.attribution).toBeNull();
  });

  it("walks only as many pages as it was asked for", async () => {
    const { entry, attribution } = await world();
    const { fetch, seen } = door(stream(entry, attribution));
    const items: SyncItem[] = [];
    for await (const item of createReader({ base: BASE, fetch }).sync({
      from: 0,
      limit: 2,
      pages: 1,
    })) {
      items.push(item);
    }
    expect(items).toHaveLength(2);
    expect(seen.paths).toHaveLength(1);
  });
});

describe("the reader kit's client: attribution and the citation", () => {
  it("answers one entry's block, and cites it in one line", async () => {
    const { attribution, entryId } = await world();
    const { fetch } = door((url) =>
      url.pathname === `/entries/${entryId}/attribution`
        ? { status: 200, body: attribution }
        : null,
    );
    const reader = createReader({ base: BASE, fetch });
    const block = await reader.attribution(entryId);
    expect(block.citation).toBe(attribution["citation"]);
    expect(reader.cite(block)).toBe(block.citation);
    expect(reader.cite(null)).toBe("(no attribution)");
  });

  it("names the validators in the line it cites", async () => {
    const { attribution } = await world();
    const citation = attribution["citation"] as string;
    const validators = attribution["validators"] as { operator: string }[];
    expect(validators.length).toBeGreaterThan(0);
    for (const row of validators) expect(citation).toContain(row.operator);
  });
});

describe("the reader kit's client: the bundle and the proof", () => {
  it("writes the three files npm run export writes", async () => {
    const { entry, bundle, entryId } = await world();
    const events = bundle["events"] as { seq: number }[];
    const seals = bundle["seals"] as { seq: number }[];
    const captures = bundle["captures"] as Record<string, Json>;

    const fetch: KitFetch = async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      const path = url.pathname;
      const json = (body: unknown, status = 200): Response =>
        new Response(JSON.stringify(body), {
          status,
          headers: { "content-type": "application/json" },
        });

      if (path === `/entries/${entryId}`) return json(entry);
      if (path === "/events") {
        const head = events[events.length - 1]?.seq ?? null;
        return json({ events, head });
      }
      if (path === "/seals") {
        const head = seals[seals.length - 1]?.seq ?? null;
        return json({ seals, head });
      }
      if (path === "/operators") return json({ operators: [] });
      if (path.startsWith("/captures/") && path.endsWith("/sidecar")) {
        return json({ error: "not_found" }, 404);
      }
      if (path.startsWith("/captures/")) {
        const hash = decodeURIComponent(path.slice("/captures/".length));
        const capture = captures[hash];
        if (capture === undefined) return json({ error: "not_found" }, 404);
        return new Response(
          base64Decode(capture["body_base64"] as string) as BodyInit,
          {
            status: 200,
            headers: {
              "content-type":
                (capture["content_type"] as string | null) ?? "text/plain",
            },
          },
        );
      }
      return json({ error: "not_found" }, 404);
    };

    const dir = await mkdtemp(join(tmpdir(), "nmk-kit-"));
    const written = await createReader({ base: BASE, fetch }).exportBundle(
      entryId,
      dir,
    );

    expect(written.entryPath.endsWith("entry.json")).toBe(true);
    expect(written.bundlePath.endsWith("log.json")).toBe(true);
    expect(written.attributionPath.endsWith("attribution.json")).toBe(true);

    const writtenEntry = JSON.parse(
      await readFile(written.entryPath, "utf8"),
    ) as Json;
    expect(writtenEntry["id"]).toBe(entryId);
    const writtenBlock = JSON.parse(
      await readFile(written.attributionPath, "utf8"),
    ) as Json;
    expect(typeof writtenBlock["citation"]).toBe("string");
    const writtenBundle = JSON.parse(
      await readFile(written.bundlePath, "utf8"),
    ) as Json;
    expect((writtenBundle["events"] as unknown[]).length).toBe(events.length);
  });

  it("runs the kernel's verifier over the committed fixtures and calls them clean", async () => {
    const { fetch } = door(() => null);
    const reader = createReader({ base: BASE, fetch });
    const report = await reader.verify(
      join(FIXTURES, "verified-entry.json"),
      join(FIXTURES, "log.json"),
    );
    expect(report.diffs).toEqual([]);
    expect(report.ok).toBe(true);
  });

  it("names a hand-edited entry rather than calling it clean", async () => {
    const entry = await fixture("verified-entry.json");
    entry["claim"] = "gpt-5 input price is $0.25 per million tokens";
    const dir = await mkdtemp(join(tmpdir(), "nmk-kit-"));
    const edited = join(dir, "entry.json");
    const { writeFile } = await import("node:fs/promises");
    await writeFile(edited, JSON.stringify(entry), "utf8");

    const { fetch } = door(() => null);
    const report = await createReader({ base: BASE, fetch }).verify(
      edited,
      join(FIXTURES, "log.json"),
    );
    expect(report.ok).toBe(false);
    expect(report.diffs.some((diff) => diff.check === "signature")).toBe(true);
  });
});

describe("the kit command line", () => {
  function sink() {
    const out: string[] = [];
    const err: string[] = [];
    return {
      out,
      err,
      io: {
        stdout: (line: string) => out.push(line),
        stderr: (line: string) => err.push(line),
      },
    };
  }

  /** The reader every verb below is run over. */
  async function reader() {
    const { entry, attribution, entryId } = await world();
    const { fetch } = door((url) => {
      if (url.pathname === `/read/${entryId}`) {
        return {
          status: 200,
          body: {
            entry,
            sidecar: {
              effective_tier: "stated",
              verification_class: "registered",
            },
          },
        };
      }
      if (url.pathname === `/entries/${entryId}/attribution`) {
        return { status: 200, body: attribution };
      }
      return null;
    });
    return {
      make: () => createReader({ base: BASE, fetch }),
      entryId,
      attribution,
    };
  }

  it("prints the attribution after every fact by default", async () => {
    const { make, entryId, attribution } = await reader();
    const s = sink();
    expect(await runKit(["read", BASE, entryId], s.io, make)).toBe(0);
    const printed = s.out.join("\n");
    expect(printed).toContain("status verified");
    expect(printed).toContain("class registered");
    expect(printed).toContain(`cite: ${attribution["citation"] as string}`);
    expect(printed).toContain("validator:");
  });

  it("silences it on --no-attribution, and prints one object on --json", async () => {
    const { make, entryId } = await reader();
    const quiet = sink();
    expect(
      await runKit(["read", BASE, entryId, "--no-attribution"], quiet.io, make),
    ).toBe(0);
    expect(quiet.out.join("\n")).not.toContain("cite:");

    const machine = sink();
    expect(
      await runKit(["read", BASE, entryId, "--json"], machine.io, make),
    ).toBe(0);
    const parsed = JSON.parse(machine.out.join("\n")) as Json;
    expect(parsed["verification_class"]).toBe("registered");
    expect(parsed["attribution"]).not.toBeNull();
  });

  it("cites one entry in one line", async () => {
    const { make, entryId, attribution } = await reader();
    const s = sink();
    expect(await runKit(["cite", BASE, entryId], s.io, make)).toBe(0);
    expect(s.out).toEqual([attribution["citation"] as string]);
  });

  it("verifies the committed fixtures and exits 0", async () => {
    const s = sink();
    const code = await runKit(
      [
        "verify",
        join(FIXTURES, "verified-entry.json"),
        join(FIXTURES, "log.json"),
      ],
      s.io,
      () => createReader({ base: BASE, fetch: async () => new Response("{}") }),
    );
    expect(code).toBe(0);
    expect(s.out[0]).toBe("ok");
  });

  it("refuses a verb it does not have, and a flag it does not know", async () => {
    const { make } = await reader();
    const first = sink();
    expect(await runKit(["delete", BASE], first.io, make)).toBe(2);
    expect(first.err.join("\n")).toContain("usage:");

    const second = sink();
    expect(
      await runKit(["read", BASE, "--nonsense", "x"], second.io, make),
    ).toBe(2);
  });

  it("prints a door's refusal and exits 1", async () => {
    const { fetch } = door(() => ({ status: 404, body: { error: "not_found" } }));
    const s = sink();
    const code = await runKit(["read", BASE, "nmk_01NOPE"], s.io, () =>
      createReader({ base: BASE, fetch }),
    );
    expect(code).toBe(1);
    expect(s.out.join("\n")).toContain("refused 404 not_found");
  });
});

describe("the kit command line: the page count", () => {
  it("refuses a --pages that is not a whole number of pages", async () => {
    const { entry, attribution, entryId } = await world();
    const { fetch } = door((url) =>
      url.pathname === "/sync"
        ? {
            status: 200,
            body: {
              from: 0,
              head: 1,
              events: [
                {
                  seq: 1,
                  kind: "entry",
                  event: { seq: 1, type: "submission", entry_id: entryId },
                  entry,
                  sidecar: { verification_class: "registered" },
                  attribution,
                },
              ],
            },
          }
        : null,
    );
    const make = () => createReader({ base: BASE, fetch });
    for (const bad of ["0", "-1", "half", "1.5"]) {
      const out: string[] = [];
      const err: string[] = [];
      const code = await runKit(
        ["sync", BASE, "--from", "0", "--pages", bad],
        { stdout: (line) => out.push(line), stderr: (line) => err.push(line) },
        make,
      );
      expect(code, `--pages ${bad}`).toBe(2);
      expect(out).toEqual([]);
    }

    const out: string[] = [];
    expect(
      await runKit(
        ["sync", BASE, "--from", "0", "--pages", "1"],
        { stdout: (line) => out.push(line), stderr: () => {} },
        make,
      ),
    ).toBe(0);
    expect(out.join("\n")).toContain("items 1");
  });
});

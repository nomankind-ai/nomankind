/**
 * The mirror page, the footer link, and the route that serves them (M23).
 *
 * Whitepaper Section 11: the sealed log is exported daily to a public
 * repository under CC0, and exit is a protocol right. So the page has one job a
 * test can hold it to — say what was exported, and say how to check a clone of
 * it without this site — and two empty states that are different facts: an
 * environment that pushes nothing, and one whose first export is still owed.
 *
 * `renderMirror` is pure, so every assertion below hands it a shape built by
 * hand: no Worker, no database, no clock. The route test is the one place a
 * request appears, and it checks only the split — HTML to a browser, and null to
 * everyone else so the JSON route answers instead.
 */

import { describe, expect, it } from "vitest";

import type { D1Like, D1LikeStatement } from "../src/storage/d1.js";
import { renderApi } from "../src/ui/pages/api.js";
import { renderMirror } from "../src/ui/pages/mirror.js";
import { renderStatus } from "../src/ui/pages/status.js";
import type { MirrorData, PageContext } from "../src/ui/types.js";
import type { Env } from "../src/worker/env.js";
import { handlePages } from "../src/worker/pages.js";

const ctx: PageContext = {
  environment: "demo",
  path: "/mirror/latest",
  origin: "https://demo.nomankind.ai",
};

const REPOSITORY = "https://github.com/nomankind-ai/log";

const RECORD: NonNullable<MirrorData["latest"]> = {
  date: "2026-09-10",
  exported_at: "2026-09-10T00:04:11.000Z",
  commit: "9f2c1ab4c5d6e7f8091a2b3c4d5e6f7081920304",
  tree: "1122334455667788990011223344556677889900",
  head: 54,
  seal_seq: 11,
  entries: 9,
  files_changed: 3,
  url: `${REPOSITORY}/tree/9f2c1ab4c5d6e7f8091a2b3c4d5e6f7081920304/demo`,
  raw_url:
    "https://raw.githubusercontent.com/nomankind-ai/log/9f2c1ab4c5d6e7f8091a2b3c4d5e6f7081920304/demo/mirror.json",
};

function data(overrides: Partial<MirrorData> = {}): MirrorData {
  return {
    configured: true,
    kind: "github",
    repository: REPOSITORY,
    branch: "main",
    path: "demo",
    latest: RECORD,
    ...overrides,
  };
}

/** Whitespace collapsed, so a wrapped sentence can be asserted as a sentence. */
function flat(document: string): string {
  return document.replace(/\s+/g, " ");
}

describe("renderMirror", () => {
  const page = renderMirror(ctx, data());

  it("says what the mirror is and where this environment writes", () => {
    expect(page).toContain("<title>Mirror · nomankind</title>");
    expect(flat(page)).toContain("under CC0");
    expect(flat(page)).toContain("Leaving is a protocol right");
    expect(page).toContain(`<span class="mono">demo</span>`);
    expect(page).toContain(`<span class="mono">main</span>`);
  });

  it("shows the export record the sweep wrote, every field of it", () => {
    for (const name of [
      "date",
      "exported_at",
      "head",
      "seal_seq",
      "entries",
      "files_changed",
      "commit",
      "tree",
    ]) {
      expect(page, `${name} is not on the page`).toContain(
        `<span class="field-name">${name}</span>`,
      );
    }
    expect(page).toContain("2026-09-10");
    expect(page).toContain("2026-09-10 00:04:11Z");
    expect(page).toContain(">54<");
    expect(page).toContain(">11<");
    expect(page).toContain(RECORD.commit);
    expect(page).toContain(RECORD.tree);
  });

  it("links the commit and the export's own mirror.json", () => {
    expect(page).toContain(`href="${RECORD.url}"`);
    expect(page).toContain(`href="${RECORD.raw_url}"`);
    expect(page).toContain(">mirror.json</a>");
  });

  it("gives the verify commands with this environment's own directory", () => {
    expect(page).toContain(`git clone ${REPOSITORY}`);
    expect(page).toContain("npm run verify-mirror -- ../log/demo");
    expect(page).toContain("--captures");
    expect(page).toContain("--entry");
  });

  it("points at the fork documentation in the code repository", () => {
    expect(page).toContain(
      "https://github.com/nomankind-ai/nomankind/blob/main/docs/FORK.md",
    );
    expect(page).toContain(">docs/FORK.md</a>");
  });

  it("says the captures are not in the mirror, only their hashes", () => {
    expect(flat(page)).toContain(
      "Snapshots are not in the mirror, only their hashes",
    );
  });

  it("says in words that this environment pushes nothing, when it does not", () => {
    const page = renderMirror(
      ctx,
      data({ configured: false, kind: "unavailable", latest: null }),
    );
    expect(flat(page)).toContain(
      "The mirror is not configured on this environment",
    );
    // Not configured is not a missing export: an environment that pushes
    // nothing is owed nothing, and the other empty state would say it was.
    expect(page).not.toContain("No export yet");
    expect(page).toContain(`git clone ${REPOSITORY}`);
  });

  it("says the first export is owed, when one is", () => {
    const page = renderMirror(ctx, data({ latest: null }));
    expect(flat(page)).toContain(
      "No export yet; the first sweep after 00:00 UTC makes one",
    );
    expect(flat(page)).not.toContain(
      "The mirror is not configured on this environment",
    );
    expect(page).not.toContain(RECORD.commit);
  });

  it("never lets a record's own strings become markup", () => {
    const hostile = renderMirror(
      ctx,
      data({
        path: `demo"><script>x</script>`,
        latest: { ...RECORD, commit: `<script>x</script>`, url: "javascript:x" },
      }),
    );
    expect(hostile).not.toContain("<script>x</script>");
    expect(hostile).toContain("&lt;script&gt;");
    // A href safeHref refuses is plain text, so the commit is never lost and
    // never linked either.
    expect(hostile).not.toContain('href="javascript:x"');
  });

  it("carries no script and no inline style", () => {
    for (const document of [
      page,
      renderMirror(ctx, data({ latest: null })),
      renderMirror(ctx, data({ configured: false, kind: "unavailable" })),
    ]) {
      expect(document).not.toContain("<script");
      expect(document).not.toContain(' style="');
    }
  });
});

describe("the footer's mirror link", () => {
  it("is on every page the shell renders, between repository and paper", () => {
    const pages = [
      renderMirror(ctx, data()),
      renderApi(ctx),
      renderStatus(ctx, {
        asOf: null,
        counters: {
          lastSweepAt: null,
          lastSweepAge: null,
          lastSweepTrigger: null,
          stagesOk: 0,
          stagesTotal: 0,
          stagesFailing: 0,
          stagesAttention: 0,
          sealedHead: null,
          newestSealSeq: null,
          unsealedEvents: 0,
          seals: 0,
          witnessedSeals: 0,
          witnessKind: "none",
        },
        stages: [],
        exercised: [],
      }),
    ];
    for (const document of pages) {
      expect(document).toContain(`<a href="/mirror/latest">Mirror</a>`);
      const footer = document.slice(document.indexOf("<footer"));
      expect(footer.indexOf("Repository")).toBeLessThan(
        footer.indexOf(">Mirror<"),
      );
      expect(footer.indexOf(">Mirror<")).toBeLessThan(
        footer.indexOf("Whitepaper"),
      );
      // Ours and internal: no new tab, no nofollow, no referrer stripping.
      expect(document).not.toContain(
        `<a href="/mirror/latest" target="_blank"`,
      );
    }
  });
});

/**
 * A database that holds nothing: the route's own reading is what is under test,
 * not the query, so the newest export comes back null and the page renders its
 * owed-an-export state.
 */
function emptyDatabase(): D1Like {
  const statement: D1LikeStatement = {
    bind: () => statement,
    first: async () => null,
    all: async () => ({ results: [], success: true }),
    run: async () => ({ results: [], success: true }),
  };
  return {
    prepare: () => statement,
    batch: async () => [],
    exec: async () => ({ count: 0, duration: 0 }),
  };
}

function env(): Env {
  return {
    DB: emptyDatabase(),
    CAPTURES: {} as Env["CAPTURES"],
    ENVIRONMENT: "demo",
    MAINTAINER_AGENT_ID: "",
  };
}

describe("GET /mirror/latest", () => {
  const now = new Date("2026-09-10T09:00:00.000Z");

  function get(on: Env): Promise<Response | null> {
    return handlePages(
      new Request("https://demo.nomankind.ai/mirror/latest", {
        headers: { accept: "text/html,application/xhtml+xml" },
      }),
      on,
      { now },
    );
  }

  it("renders the page to a browser", async () => {
    const response = await get(env());
    expect(response).not.toBeNull();
    expect(response?.status).toBe(200);
    expect(response?.headers.get("content-type")).toBe(
      "text/html; charset=utf-8",
    );
    expect(response?.headers.get("vary")).toBe("Accept");
    const body = await response!.text();
    expect(body).toContain("<title>Mirror · nomankind</title>");
    // No MIRROR_TOKEN on this environment, so the adapter is unavailable and
    // the page says so rather than reporting an export that is not owed.
    expect(flat(body)).toContain(
      "The mirror is not configured on this environment",
    );
  });

  it("reads the adapter and the newest export, not a literal", async () => {
    // The same empty database, one secret different: the environment can push
    // now, so the first export is owed rather than never coming.
    const configured = { ...env(), MIRROR_TOKEN: "test-token" } as Env;
    const body = await (await get(configured))!.text();
    expect(flat(body)).toContain(
      "No export yet; the first sweep after 00:00 UTC makes one",
    );
    expect(flat(body)).not.toContain(
      "The mirror is not configured on this environment",
    );
  });

  it("leaves every other caller to the JSON route", async () => {
    for (const accept of ["application/json", "*/*"]) {
      const response = await handlePages(
        new Request("https://demo.nomankind.ai/mirror/latest", {
          headers: { accept },
        }),
        env(),
        { now },
      );
      expect(response, `${accept} was answered here`).toBeNull();
    }
  });
});

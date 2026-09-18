/**
 * The reader kit's page (M25c).
 *
 * The kit is a handful of commands somebody runs from outside: read an entry,
 * sync the delta, verify what came back, confirm a fact from an account they
 * already have. Its document is served here rather than only on GitHub, for the
 * same reason the fork guide is — what a reader needs in order to use this log
 * without asking anybody for anything must not live somewhere the log does not
 * answer for.
 *
 * Four things are held here: the docs hub links it, the API page names it and
 * says what a browser may do cross-origin, the page itself renders from the
 * generated module's own bytes, and the dry-run page tells a community member
 * they need none of what is on it.
 *
 * Pure but for the route: the pages are rendered directly, and the one request
 * that goes through `handlePages` reads no store — a document is a constant, and
 * the database below refuses every statement to prove it.
 */

import { describe, expect, it } from "vitest";

import { READER_KIT_MARKDOWN } from "../src/ui/docs.generated.js";
import type { D1Like } from "../src/storage/d1.js";
import { renderApi } from "../src/ui/pages/api.js";
import { renderDocs } from "../src/ui/pages/docs.js";
import {
  READER_KIT_DOCUMENT,
  renderDocument,
} from "../src/ui/pages/document.js";
import { renderDryRun } from "../src/ui/pages/dry-run.js";
import type { PageContext } from "../src/ui/types.js";
import type { Env } from "../src/worker/env.js";
import { handlePages } from "../src/worker/pages.js";

const NOW = new Date("2026-09-17T00:00:00.000Z");

const ctx: PageContext = {
  environment: "demo",
  path: "/docs",
  origin: "https://demo.nomankind.ai",
  canonical_origin: "https://demo.nomankind.ai",
};

/** Flattened, so an assertion is about the words and not about the wrapping. */
function flat(page: string): string {
  return page.replace(/\s+/g, " ");
}

/** A database that answers nothing: a document page must never reach for one. */
function refusingDatabase(): D1Like {
  const refuse = (): never => {
    throw new Error("a document page read the database");
  };
  return {
    prepare: refuse,
    batch: refuse,
    exec: refuse,
  } as unknown as D1Like;
}

describe("the docs hub links the kit", () => {
  const page = flat(renderDocs(ctx));

  it("names it under Take it with you, with its one line", () => {
    expect(page).toContain(
      `<a class="step" href="/docs/reader-kit" ><span class="step-t">Reader kit</span> ` +
        `<span class="note">Read, sync and verify without a key; confirm from your community.</span></a >`,
    );
  });

  it("keeps it in the group that is about leaving with the record", () => {
    const group = page.slice(page.indexOf("Take it with you"));
    expect(group).toContain("/docs/reader-kit");
    // Beside the fork guide, which is the other half of the same idea.
    expect(group.indexOf("/docs/fork")).toBeLessThan(
      group.indexOf("/docs/reader-kit"),
    );
  });
});

describe("the API page points at it", () => {
  const page = renderApi(ctx);
  const one = flat(page);

  it("carries a Reader kit section that links the document", () => {
    expect(one).toContain(`<h2 class="panel-title">Reader kit</h2>`);
    expect(one).toContain(`<a href="/docs/reader-kit">The reader kit</a>`);
    expect(one).toContain("npm run confirm");
  });

  it("says the read doors answer any origin without credentials", () => {
    expect(one).toContain("access-control-allow-origin: *");
    expect(one).toContain("access-control-expose-headers");
    expect(one).toContain("GET, HEAD, OPTIONS");
    expect(one).toContain("No credentials header is sent, ever");
  });

  it("says a write door carries none of it", () => {
    const section = one.slice(one.indexOf("Reader kit</h2>"));
    expect(section).toContain("POST /keys/free");
    expect(section).toContain("no write door carries any of this");
  });

  it("names the user-agent note", () => {
    const section = one.slice(one.indexOf("Reader kit</h2>"));
    expect(section).toContain("User-Agent");
    expect(section).toContain("nomankind-reader-kit/&lt;version&gt;");
    // The stock Python user agent, which both hostnames answer with no edge
    // rule behind it — the note the kit's own document carries, said here
    // where a caller reads the doors.
    expect(section).toContain("Python-urllib");
  });
});

describe("the kit's own page", () => {
  it("renders from the generated module rather than from the file system", () => {
    expect(READER_KIT_DOCUMENT.markdown).toBe(READER_KIT_MARKDOWN);
    expect(READER_KIT_DOCUMENT.sourcePath).toBe("docs/READER-KIT.md");
    expect(READER_KIT_MARKDOWN.length).toBeGreaterThan(0);
  });

  it("crumbs, heads and names the source", () => {
    const page = renderDocument({ ...ctx, path: "/docs/reader-kit" }, READER_KIT_DOCUMENT);
    expect(page).toContain("<h1>Reader kit</h1>");
    expect(flat(page)).toContain(
      `<div class="crumbs mono"> <a href="/docs">Docs</a><span>/</span><span>Reader kit</span> </div>`,
    );
    expect(flat(page)).toContain(
      `${READER_KIT_DOCUMENT.note} · <span class="mono">docs/READER-KIT.md</span>`,
    );
    // The page prints the title, so the document is rendered under it and the
    // opening heading is not printed twice.
    expect(page.match(/<h1>/g) ?? []).toHaveLength(1);
    expect(page).not.toContain("<script");
  });

  // D-142: the reply is the whole of the answer, so the document says that
  // first and keeps the key-bound walkthrough as the upgrade after it.
  it("leads the confirming half with the no-tool reply, and both lines", () => {
    const one = flat(
      renderDocument({ ...ctx, path: "/docs/reader-kit" }, READER_KIT_DOCUMENT),
    );
    expect(one).toContain("Reply, no tool");
    expect(one).toContain(
      "nomankind-confirm-v1 &lt;entry id&gt; approve span-present attest:nomankind-independence-v1",
    );
    expect(one).toContain(
      "nomankind-confirm-v1 &lt;entry id&gt; reject span-absent attest:nomankind-independence-v1",
    );
    expect(one).toContain("no tool, no key, no account anywhere but the one");
    expect(one).toContain("account-bound");
    expect(one).toContain("2032-01-01");
    expect(one.indexOf("Reply, no tool")).toBeLessThan(
      one.indexOf("Confirming an entry in public"),
    );
  });

  it("is served at /docs/reader-kit, HTML to any reader", async () => {
    const env = {
      DB: refusingDatabase(),
      CAPTURES: {},
      ENVIRONMENT: "local",
      MAINTAINER_AGENT_ID: "",
    } as unknown as Env;
    const response = await handlePages(
      new Request("https://app.nomankind.ai/docs/reader-kit", {
        headers: { accept: "text/html" },
      }),
      env,
      { now: NOW },
    );
    expect(response).not.toBeNull();
    expect(response!.status).toBe(200);
    expect(response!.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(await response!.text()).toContain("<h1>Reader kit</h1>");
  });
});

describe("the dry run sends a community member to the kit", () => {
  const page = flat(renderDryRun(ctx));

  it("says a confirmation needs no registration at all", () => {
    expect(page).toContain("npm run confirm");
    expect(page).toContain(`<a href="/docs/reader-kit">the reader kit</a>`);
    expect(page).toContain("No domain, no DNS record, no key here.");
  });
});

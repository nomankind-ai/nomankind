/**
 * The committed documents module, against a fresh generation (D-104).
 *
 * A Worker has no file system, so the three documents it serves are read from
 * the repository ahead of time and committed as src/ui/docs.generated.ts,
 * exactly as the entry validator is compiled ahead of time and committed
 * (D-041). Which leaves one way for the site to start lying: somebody edits the
 * whitepaper and does not run `npm run gen:docs`, and the page goes on serving
 * the version before the edit while the repository shows the version after it.
 *
 * So this is the validator's own test: regenerate in memory from the documents
 * on disk and compare with the committed file byte for byte. A forgotten run
 * fails the suite rather than shipping a page that disagrees with its source.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { DOCUMENT_SOURCES, generateDocsSource } from "../src/cli/gen-docs.js";
import {
  FORK_MARKDOWN,
  FORK_SOURCE_PATH,
  SUMMARY_MARKDOWN,
  SUMMARY_SOURCE_PATH,
  WHITEPAPER_MARKDOWN,
  WHITEPAPER_SOURCE_PATH,
} from "../src/ui/docs.generated.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const generatedPath = fileURLToPath(
  new URL("../src/ui/docs.generated.ts", import.meta.url),
);

function read(path: string): string {
  return readFileSync(`${root}${path}`, "utf8");
}

describe("the generated documents module", () => {
  it("is exactly what gen:docs writes today", () => {
    const committed = readFileSync(generatedPath, "utf8");
    expect(committed).toBe(generateDocsSource(read));
  });

  it("says it is generated and names the command that writes it", () => {
    const committed = readFileSync(generatedPath, "utf8");
    expect(committed).toContain("GENERATED — do not edit");
    expect(committed).toContain("npm run gen:docs");
  });

  it("names the three documents and where each was read from", () => {
    expect(DOCUMENT_SOURCES.map((each) => each.path)).toEqual([
      "docs/FORK.md",
      "paper/WHITEPAPER.md",
      "paper/SUMMARY.md",
    ]);
    expect(FORK_SOURCE_PATH).toBe("docs/FORK.md");
    expect(WHITEPAPER_SOURCE_PATH).toBe("paper/WHITEPAPER.md");
    expect(SUMMARY_SOURCE_PATH).toBe("paper/SUMMARY.md");
  });

  it("holds each document verbatim, to the last byte", () => {
    expect(FORK_MARKDOWN).toBe(read("docs/FORK.md"));
    expect(WHITEPAPER_MARKDOWN).toBe(read("paper/WHITEPAPER.md"));
    expect(SUMMARY_MARKDOWN).toBe(read("paper/SUMMARY.md"));
  });

  /**
   * The point of the pin: an edited document with no regeneration is a
   * difference this test can see, and the message it fails with is the run the
   * author forgot.
   */
  it("fails when a document has moved on without a regeneration", () => {
    const stale = generateDocsSource((path) =>
      path === "paper/SUMMARY.md" ? `${read(path)}\nOne more sentence.\n` : read(path),
    );
    expect(stale).not.toBe(readFileSync(generatedPath, "utf8"));
  });
});

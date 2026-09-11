/**
 * gen:docs: write the three served documents into a module the Worker can hold.
 *
 * Decision D-104: the whitepaper, its summary and the fork guide are served by
 * this Worker rather than only by GitHub, and a Worker has no file system to
 * read them from at run time. So they are read here and committed as string
 * constants, exactly as the entry validator is compiled ahead of time and
 * committed (D-041). test/docs-generation.test.ts regenerates this module in
 * memory and compares it with the committed one byte for byte, so an edit to a
 * document without a run of this command fails the suite rather than serving a
 * page that quietly disagrees with the repository.
 *
 * node:fs, node:path and node:url are allowed in this CLI file only; the kernel
 * and the pages stay Workers-safe.
 */

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** One document: the constant it becomes, and where it is read from. */
export interface DocumentSource {
  /** The prefix of the two exported constants, `FORK` giving `FORK_MARKDOWN`. */
  readonly constant: string;
  /** The path from the repository root, which is also what the page names. */
  readonly path: string;
}

/**
 * The three documents, in the order the docs hub lists them. Adding a fourth is
 * this list, a route, and a run of the command: nothing else reads the file
 * system on the way to a page.
 */
export const DOCUMENT_SOURCES: readonly DocumentSource[] = Object.freeze([
  Object.freeze({ constant: "FORK", path: "docs/FORK.md" }),
  Object.freeze({ constant: "WHITEPAPER", path: "paper/WHITEPAPER.md" }),
  Object.freeze({ constant: "SUMMARY", path: "paper/SUMMARY.md" }),
]);

/** The repository root, from this module. Compiled, it sits at dist/cli/. */
const ROOT = fileURLToPath(new URL("../../", import.meta.url));

/** The committed module this command writes. */
const DEFAULT_TARGET = fileURLToPath(
  new URL("../../src/ui/docs.generated.ts", import.meta.url),
);

const HEADER = `/**
 * The three documents this Worker serves, as strings. GENERATED — do not edit.
 *
 * Written by \`npm run gen:docs\` from the files named below, because a Worker
 * has no file system to read them from at run time (D-104). Edit the documents
 * and run the command; test/docs-generation.test.ts compares this file with a
 * fresh generation byte for byte and fails when the two have drifted.
 */

`;

/**
 * The module's source, from a reader that hands back each document's text.
 *
 * Taking the reader rather than reading here is what lets the test regenerate
 * in memory: the same function, the same bytes, no temporary file.
 */
export function generateDocsSource(
  read: (path: string) => string,
): string {
  const parts: string[] = [HEADER];
  for (const source of DOCUMENT_SOURCES) {
    const text = read(source.path);
    parts.push(
      `/** ${source.path}, verbatim. */\n` +
        `export const ${source.constant}_SOURCE_PATH = ${JSON.stringify(source.path)};\n\n` +
        `export const ${source.constant}_MARKDOWN = ${JSON.stringify(text)};\n\n`,
    );
  }
  return `${parts.join("").trimEnd()}\n`;
}

export interface GenDocsIo {
  stdout: (line: string) => void;
}

export interface GenDocsResult {
  path: string;
  bytes: number;
}

/** Generate the module and write it to `path`, overwriting what is there. */
export async function genDocs(
  path: string,
  io: GenDocsIo,
): Promise<GenDocsResult> {
  const target = resolve(path);
  const texts = new Map<string, string>();
  for (const source of DOCUMENT_SOURCES) {
    texts.set(source.path, await readFile(resolve(ROOT, source.path), "utf8"));
  }
  const generated = generateDocsSource((each) => texts.get(each) ?? "");
  await writeFile(target, generated, "utf8");

  const bytes = Buffer.byteLength(generated, "utf8");
  io.stdout(`path: ${target}`);
  io.stdout(`bytes: ${bytes}`);

  return { path: target, bytes };
}

/* c8 ignore start -- the process entry point, exercised by running the CLI. */
if (
  process.argv[1] !== undefined &&
  import.meta.filename === resolve(process.argv[1])
) {
  const path = process.argv[2] ?? DEFAULT_TARGET;
  await genDocs(path, { stdout: (line: string) => console.log(line) });
}
/* c8 ignore stop */

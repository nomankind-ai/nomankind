/**
 * gen:validator: write the ahead-of-time entry validator.
 *
 * Decision D-041: the Worker cannot compile a schema at run time, so the
 * validator is generated here and committed. Run `npm run gen:validator` after
 * any change to schema/nomankind-entry-schema.json; test/schema.test.ts compares
 * the committed file against a fresh generation byte for byte, so a forgotten
 * run fails the suite rather than shipping a stale validator.
 *
 * node:fs, node:path and node:url are allowed in this CLI file only; the kernel
 * itself stays Workers-safe.
 */

import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { generateValidatorSource } from "./validator-source.js";

/**
 * The committed validator, relative to this module. Compiled, this file sits at
 * dist/cli/, so two levels up is the repository root either way.
 */
const DEFAULT_TARGET = fileURLToPath(
  new URL("../../src/schema-validator.generated.ts", import.meta.url),
);

export interface GenValidatorIo {
  stdout: (line: string) => void;
}

export interface GenValidatorResult {
  path: string;
  bytes: number;
}

/** Generate the validator and write it to `path`, overwriting what is there. */
export async function genValidator(
  path: string,
  io: GenValidatorIo,
): Promise<GenValidatorResult> {
  const target = resolve(path);
  const source = generateValidatorSource();
  await writeFile(target, source, "utf8");

  const bytes = Buffer.byteLength(source, "utf8");
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
  await genValidator(path, { stdout: (line: string) => console.log(line) });
}
/* c8 ignore stop */

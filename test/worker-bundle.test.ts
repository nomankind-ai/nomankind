/**
 * What actually reaches the edge.
 *
 * Decision D-041: Cloudflare Workers forbid the `Function` constructor, which is
 * how Ajv builds a validator at run time, so the schema is compiled ahead of
 * time into src/schema-validator.generated.ts and Ajv's compiler never enters
 * the Worker's module graph. That is a fact about the emitted bundle, not about
 * the source, so this test asks the real bundler: `wrangler deploy --dry-run`
 * writes the bundle to a temporary directory and the bytes are read back.
 *
 * Two bundles are built. The Worker's own entry point is what deploys today.
 * The kernel barrel, src/index.ts, is every module the Worker may import as
 * later milestones mount their routes — the validator among them — so it is the
 * one that proves the ahead-of-time validator is bundled and still carries no
 * compiler. An import of Ajv's compiler anywhere under src/ fails this test.
 *
 * Nothing here reaches Cloudflare: --dry-run is the whole point.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { SCHEMA_ID } from "../src/schema.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const WRANGLER = join(ROOT, "node_modules", "wrangler", "bin", "wrangler.js");

/** Long enough for a cold esbuild run on a loaded machine. */
const BUNDLE_TIMEOUT_MS = 120_000;

const outDirs: string[] = [];

/**
 * Bundle one entry point and return the emitted JavaScript. `entry` is a path
 * relative to the repository root, or undefined for the `main` that
 * wrangler.jsonc names.
 */
function bundle(entry?: string): string {
  const outDir = mkdtempSync(join(tmpdir(), "nomankind-bundle-"));
  outDirs.push(outDir);

  const toolPath = [
    join(ROOT, ".tools", "node", "bin"),
    join(ROOT, ".tools", "gh", "bin"),
    process.env["PATH"] ?? "",
  ].join(delimiter);

  const args = [WRANGLER, "deploy"];
  if (entry !== undefined) {
    args.push(entry);
  }
  args.push("--dry-run", "--outdir", outDir);

  const result = spawnSync(process.execPath, args, {
    cwd: ROOT,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: toolPath,
      // Nothing here should reach Cloudflare; --dry-run is the whole point.
      WRANGLER_SEND_METRICS: "false",
      CI: "true",
    },
  });
  if (result.status !== 0) {
    throw new Error(
      `wrangler ${args.slice(1).join(" ")} failed: ${result.stdout ?? ""}${result.stderr ?? ""}`,
    );
  }
  return readFileSync(join(outDir, "index.js"), "utf8");
}

describe("the deployed bundle", () => {
  let worker: string;
  let kernel: string;

  beforeAll(() => {
    worker = bundle();
    kernel = bundle("src/index.ts");
  }, BUNDLE_TIMEOUT_MS);

  afterAll(() => {
    for (const dir of outDirs) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("bundles something to begin with", () => {
    expect(worker.length).toBeGreaterThan(0);
    expect(kernel.length).toBeGreaterThan(0);
  });

  for (const [name, source] of [
    ["the Worker entry point", () => worker],
    ["the kernel barrel", () => kernel],
  ] as const) {
    it(`builds no validator at run time from ${name}`, () => {
      // The one thing workerd forbids outright.
      expect(source()).not.toContain("new Function(");
    });

    it(`pulls no Ajv compiler into ${name}`, () => {
      // esbuild writes each bundled module's path above it, so the compiler's
      // own directory names it exactly.
      expect(source()).not.toContain("ajv/dist/compile");
      expect(source()).not.toContain("ajv/dist/2020");
      expect(source()).not.toContain("ajv/dist/standalone");
    });
  }

  it("carries the ahead-of-time validator, schema and all", () => {
    expect(kernel).toContain("nomankind-entry-schema");
    expect(kernel).toContain(SCHEMA_ID);
  });
});

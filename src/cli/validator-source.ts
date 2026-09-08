/**
 * The entry validator's source text, generated ahead of time.
 *
 * Cloudflare Workers forbid the `Function` constructor, and that is exactly how
 * Ajv builds a validator at run time. So the schema is compiled here, at build
 * time, and Ajv's standalone code generation writes the result out as a module
 * the Worker imports like any other (decision D-041). Nothing under src/ but
 * this file and its CLI ever loads Ajv's compiler.
 *
 * The Ajv instance is built with exactly the options src/schema.ts used when it
 * compiled at import — strict mode on, all errors collected, ajv-formats added
 * — so the generated validator enforces the same rules the hand-built one did.
 * `buildAjv` is exported so a test can pin those options on the real instance.
 *
 * `standaloneCode` emits ES module exports under `code.esm`, but Ajv's runtime
 * helpers still arrive as CommonJS `require(...)` calls, which are not ES module
 * syntax and which esbuild, tsc and vitest each treat differently. So every
 * require is rewritten, deterministically and in source order, into a hoisted
 * static import: `require("x")` becomes `__rt0` and `import __rt0 from "x.js"`
 * goes at the top. A default import of a CommonJS module is its `module.exports`
 * object, so member access after the call site is unchanged: what was
 * `require("ajv/dist/runtime/equal").default` reads `__rt0.default`.
 *
 * The output is a pure function of the schema and of these options, so the
 * committed file can be compared against it byte for byte and never drift.
 */

import Ajv2020 from "ajv/dist/2020.js";
import type { ValidateFunction } from "ajv";
import addFormats from "ajv-formats";
import standaloneCode from "ajv/dist/standalone/index.js";

import entrySchema from "../../schema/nomankind-entry-schema.json" with { type: "json" };

/** The header the generated file carries, so nobody edits it by hand. */
const HEADER = `/**
 * GENERATED FILE. Do not edit.
 *
 * Written by \`npm run gen:validator\` from schema/nomankind-entry-schema.json,
 * the single source of truth. Edit the schema and regenerate; an edit here is
 * lost, and test/schema.test.ts fails the moment this file and the schema
 * disagree.
 */
// @ts-nocheck
`;

/** The prefix of the hoisted import names, one per required runtime module. */
const RUNTIME_PREFIX = "__rt";

/** `require("x")` or `require('x')`, with the specifier captured. */
const REQUIRE_CALL = /require\((?:"([^"]*)"|'([^']*)')\)/g;

/**
 * The Ajv instance the validator is compiled with: strict mode, every error
 * collected, ajv-formats registered, and standalone ES module code generation.
 *
 * The first three are the options src/schema.ts compiled with before D-041 and
 * are part of what the schema means; the fourth only decides where the compiled
 * code goes.
 */
export function buildAjv(): Ajv2020 {
  const ajv = new Ajv2020({
    strict: true,
    allErrors: true,
    code: { source: true, esm: true },
  });
  addFormats(ajv);
  return ajv;
}

/**
 * A CommonJS require specifier as an ES module specifier: an extensionless path
 * gets `.js`, because ES module resolution never guesses one.
 */
function moduleSpecifier(request: string): string {
  const basename = request.slice(request.lastIndexOf("/") + 1);
  return basename.includes(".") ? request : `${request}.js`;
}

/**
 * The full text of src/schema-validator.generated.ts, header and all.
 */
export function generateValidatorSource(): string {
  const ajv = buildAjv();
  const validate: ValidateFunction = ajv.compile(entrySchema);
  const compiled = standaloneCode(ajv, validate);

  // Insertion order is source order, so the names are stable run to run.
  const names = new Map<string, string>();
  const body = compiled.replace(
    REQUIRE_CALL,
    (_match: string, doubleQuoted?: string, singleQuoted?: string): string => {
      const request = doubleQuoted ?? singleQuoted ?? "";
      const existing = names.get(request);
      if (existing !== undefined) {
        return existing;
      }
      const name = `${RUNTIME_PREFIX}${names.size}`;
      names.set(request, name);
      return name;
    },
  );

  const imports = [...names].map(
    ([request, name]) =>
      `import ${name} from "${moduleSpecifier(request)}";\n`,
  );
  const prelude = imports.length === 0 ? "" : `${imports.join("")}\n`;
  return `${HEADER}${prelude}${body}\n`;
}

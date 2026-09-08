/**
 * Entry schema validation.
 *
 * The schema in `schema/` is the single source of truth; it is imported, never
 * copied into TypeScript. It is compiled ahead of time rather than at module
 * load: Cloudflare Workers forbid the `Function` constructor, which is how Ajv
 * builds a validator at run time, so `npm run gen:validator` compiles the schema
 * into src/schema-validator.generated.ts and this module imports the result
 * (decision D-041). Ajv's compiler never enters the Worker's module graph; the
 * generator lives under src/cli, and test/worker-bundle.test.ts fails if it ever
 * gets pulled back in.
 *
 * The generated validator is built with the same Ajv options this module used
 * before — strict mode, all errors, ajv-formats — pinned in test/schema.test.ts
 * against the real instance, and the committed file is compared byte for byte
 * against a fresh generation so it can never drift from the schema.
 */

import type { ErrorObject, ValidateFunction } from "ajv";

import entrySchema from "../schema/nomankind-entry-schema.json" with { type: "json" };
import { validate as generatedValidate } from "./schema-validator.generated.js";

/**
 * A log entry, as defined by the entry schema.
 *
 * Deliberately structural: the schema already states every field name, type,
 * and cross-field rule, so a hand-written interface would only duplicate it and
 * risk drifting from it. Callers narrow through `validateEntry` and then read
 * fields by their schema names.
 */
export type Entry = Record<string, unknown>;

/** A single validation failure, in terms callers can act on. */
export interface ValidationError {
  /** JSON Pointer to the offending location, e.g. `/evidence_tier`. */
  readonly path: string;
  /** Human-readable description of the rule that failed. */
  readonly message: string;
}

/** The result of validating a candidate entry. */
export type ValidationResult =
  | { readonly ok: true; readonly entry: Entry; readonly errors: readonly [] }
  | { readonly ok: false; readonly errors: readonly ValidationError[] };

/** `$id` of the schema this module validates against. */
export const SCHEMA_ID: string = entrySchema.$id;

/**
 * The generated module is exempt from type checking, so its export arrives
 * untyped; it is Ajv's own validate function and is named as one here.
 */
const validate = generatedValidate as unknown as ValidateFunction;

/**
 * Ajv reports a missing property against its parent object, with the property
 * name in `params`. Point at the missing member instead, so the path names the
 * field the caller has to fix.
 */
function pathOf(error: ErrorObject): string {
  if (error.keyword === "required") {
    const missing = (error.params as { missingProperty?: string })
      .missingProperty;
    if (typeof missing === "string") {
      return `${error.instancePath}/${missing}`;
    }
  }
  return error.instancePath;
}

function toValidationErrors(
  errors: readonly ErrorObject[] | null | undefined,
): readonly ValidationError[] {
  if (!errors || errors.length === 0) {
    return [{ path: "", message: "is not a valid entry" }];
  }
  return errors.map((error) => ({
    path: pathOf(error),
    message: error.message ?? "is invalid",
  }));
}

/**
 * Validate an arbitrary value against the entry schema.
 *
 * Never throws, and never leaks raw Ajv error objects to callers.
 */
export function validateEntry(value: unknown): ValidationResult {
  if (validate(value)) {
    return { ok: true, entry: value as Entry, errors: [] };
  }
  return { ok: false, errors: toValidationErrors(validate.errors) };
}

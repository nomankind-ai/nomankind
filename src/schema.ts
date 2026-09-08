/**
 * Entry schema validation.
 *
 * The schema in `schema/` is the single source of truth; it is imported, never
 * copied into TypeScript. One Ajv 2020 instance is built and the schema is
 * compiled once, at module load.
 */

import Ajv2020 from "ajv/dist/2020.js";
import type { ErrorObject, ValidateFunction } from "ajv";
import addFormats from "ajv-formats";

import entrySchema from "../schema/nomankind-entry-schema.json" with { type: "json" };

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

const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats(ajv);

const validate: ValidateFunction = ajv.compile(entrySchema);

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

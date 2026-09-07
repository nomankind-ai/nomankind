/**
 * Artifact hashing for norm-v1.2 (whitepaper Section 4, Snapshots).
 *
 * Three artifact kinds are hashed over exact key sets: the transcript artifact
 * of a behavior or misbehavior entry, the observation receipt artifact of an
 * observed entry, and the failure report artifact, which is whichever of the
 * two its key set names. An artifact with a missing or extra key is refused
 * rather than hashed, so an artifact hash always covers the same measurement.
 *
 * A receipt may carry `[REDACTED]` only where redaction cannot hide the claim:
 * request headers, credential- and identifier-named values under `request`, and
 * identifier-named values under `billing`. `[REDACTED]` anywhere else is a
 * load-bearing redaction and invalidates the receipt.
 *
 * The rule this module implements is published as
 * `schema/nomankind-snapshot-normalization-v1.md`; where the two disagree, the
 * document governs and this module gets fixed (D-012).
 */

import entrySchema from "../schema/nomankind-entry-schema.json";

import { canonicalize, sha256Hex } from "./hash.js";

/** The exact key set of a transcript artifact: `evidence` minus its citation. */
export const TRANSCRIPT_ARTIFACT_KEYS = [
  "model",
  "prompt",
  "parameters",
  "output",
  "predicate",
  "observed_at",
] as const;

/** The exact key set of an observation receipt artifact. */
export const RECEIPT_ARTIFACT_KEYS = [
  "method",
  "subject",
  "test",
  "request",
  "response",
  "billing",
  "observed_at",
  "observer",
] as const;

/** The redaction placeholder. A string containing it counts as redacted. */
export const REDACTED = "[REDACTED]";

/** Every reason an artifact can be refused. */
export const ARTIFACT_REFUSALS = [
  "transcript_shape",
  "receipt_shape",
  "unknown_method",
  "billing_shape",
  "redacted_load_bearing",
  "unknown_artifact",
] as const;

export type ArtifactRefusal = (typeof ARTIFACT_REFUSALS)[number];

/** The result of a check: accepted, or refused with a reason and a detail. */
export type ArtifactCheck =
  | { ok: true }
  | { ok: false; reason: ArtifactRefusal; detail: string };

/** The result of hashing: the `sha256:` hash, or the refusal that stopped it. */
export type ArtifactHashResult =
  | { ok: true; hash: string }
  | { ok: false; reason: ArtifactRefusal; detail: string };

/** A transcript artifact: the six measured fields and nothing else. */
export interface TranscriptArtifact {
  model: unknown;
  prompt: unknown;
  parameters: unknown;
  output: string;
  predicate: unknown;
  observed_at: string;
}

/** Which artifact kind a key set names. */
export type ArtifactKind = "transcript" | "receipt";

/**
 * The observation methods, read from the entry schema. The schema is the single
 * source of truth for the enum; it is never copied into TypeScript.
 */
const OBSERVATION_METHODS: readonly string[] =
  entrySchema.properties.observation.properties.method.enum;

/** The method whose receipt must carry a billing line. */
const METERED_CALL = "metered_call";

/**
 * Keys whose values are credentials. Redaction under `request` is permitted at
 * these keys and at any value they contain. Listed in the folded form keys are
 * compared in: ASCII-lowercased with `-` written as `_`, so the document's
 * `proxy-authorization` and `x-api-key` appear here as `proxy_authorization`
 * and `x_api_key`, and its `api-key` folds onto `api_key`.
 */
export const CREDENTIAL_KEYS: readonly string[] = Object.freeze([
  "authorization",
  "proxy_authorization",
  "cookie",
  "set_cookie",
  "api_key",
  "apikey",
  "x_api_key",
  "key",
  "token",
  "access_token",
  "refresh_token",
  "secret",
  "password",
  "bearer",
]);

/**
 * Keys that name an account rather than a measurement. Redaction is permitted
 * at these keys under `request` and under `billing`. Folded the same way.
 */
export const IDENTIFIER_KEYS: readonly string[] = Object.freeze([
  "account",
  "account_id",
  "organization",
  "organization_id",
  "org",
  "org_id",
  "project",
  "project_id",
  "billing_account",
  "billing_account_id",
  "customer",
  "customer_id",
  "user",
  "user_id",
  "workspace",
  "workspace_id",
  "tenant",
  "tenant_id",
]);

const CREDENTIAL_KEY_SET = normalizedKeySet(CREDENTIAL_KEYS);
const IDENTIFIER_KEY_SET = normalizedKeySet(IDENTIFIER_KEYS);

/** Keys compare ASCII-lowercased, with `-` and `_` the same character. */
function normalizeKey(key: string): string {
  let normalized = "";
  for (const character of key) {
    if (character === "-") {
      normalized += "_";
      continue;
    }
    normalized +=
      character >= "A" && character <= "Z"
        ? character.toLowerCase()
        : character;
  }
  return normalized;
}

function normalizedKeySet(keys: readonly string[]): ReadonlySet<string> {
  return new Set(keys.map(normalizeKey));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" && value !== null && !Array.isArray(value)
  );
}

/** RFC 6901 escaping for one JSON pointer segment. */
function escapePointerSegment(segment: string): string {
  return segment.replace(/~/g, "~0").replace(/\//g, "~1");
}

/**
 * Compare an object's own key set against an exact key set. Missing keys are
 * reported in key-set order, then extra keys in sorted order, so the detail of
 * a given malformed artifact is always the same string.
 */
function keySetDetail(
  value: Record<string, unknown>,
  expected: readonly string[],
): string | null {
  const present = new Set(Object.keys(value));
  for (const key of expected) {
    if (!present.has(key)) {
      return `missing key "${key}"`;
    }
  }
  const allowed = new Set<string>(expected);
  for (const key of Object.keys(value).sort()) {
    if (!allowed.has(key)) {
      return `unexpected key "${key}"`;
    }
  }
  return null;
}

/**
 * Build a transcript artifact: `model`, `prompt`, `parameters`, and `predicate`
 * copied from the entry's `evidence` unchanged, with the runner's own `output`
 * and `observed_at`. `provider_statement` is a citation, not a measurement, and
 * is never copied.
 */
export function buildTranscriptArtifact(
  evidence: unknown,
  output: string,
  observed_at: string,
): TranscriptArtifact {
  const source = isRecord(evidence) ? evidence : {};
  return {
    model: source["model"],
    prompt: source["prompt"],
    parameters: source["parameters"],
    output,
    predicate: source["predicate"],
    observed_at,
  };
}

/** A transcript artifact carries exactly the six transcript keys. */
export function checkTranscriptArtifact(value: unknown): ArtifactCheck {
  if (!isRecord(value)) {
    return {
      ok: false,
      reason: "transcript_shape",
      detail: "transcript artifact is not a JSON object",
    };
  }
  const detail = keySetDetail(value, TRANSCRIPT_ARTIFACT_KEYS);
  if (detail !== null) {
    return { ok: false, reason: "transcript_shape", detail };
  }
  return { ok: true };
}

/**
 * An observation receipt carries exactly the eight receipt keys, a `method`
 * from the schema's enum, a `billing` line exactly when the method is a metered
 * call, and no redaction of a load-bearing value.
 */
export function checkReceiptArtifact(value: unknown): ArtifactCheck {
  if (!isRecord(value)) {
    return {
      ok: false,
      reason: "receipt_shape",
      detail: "receipt artifact is not a JSON object",
    };
  }
  const detail = keySetDetail(value, RECEIPT_ARTIFACT_KEYS);
  if (detail !== null) {
    return { ok: false, reason: "receipt_shape", detail };
  }

  const method = value["method"];
  if (typeof method !== "string" || !OBSERVATION_METHODS.includes(method)) {
    return {
      ok: false,
      reason: "unknown_method",
      detail: `method ${JSON.stringify(method)} is not one of ${OBSERVATION_METHODS.join(", ")}`,
    };
  }

  const billing = value["billing"];
  if (method === METERED_CALL) {
    if (billing === null || billing === undefined) {
      return {
        ok: false,
        reason: "billing_shape",
        detail: `billing must be present for method "${METERED_CALL}"`,
      };
    }
  } else if (billing !== null) {
    return {
      ok: false,
      reason: "billing_shape",
      detail: `billing must be null for method "${method}"`,
    };
  }

  return checkRedaction(value);
}

interface RedactionContext {
  /** The receipt's top-level key this value sits under, or null at the root. */
  readonly root: string | null;
  /** The value's own key and every ancestor key below `root`. */
  readonly keys: readonly string[];
  /** Whether the value sits under `request.headers`. */
  readonly inRequestHeaders: boolean;
}

const ROOT_CONTEXT: RedactionContext = {
  root: null,
  keys: [],
  inRequestHeaders: false,
};

function childContext(
  context: RedactionContext,
  key: string,
): RedactionContext {
  if (context.root === null) {
    return { root: key, keys: [], inRequestHeaders: false };
  }
  return {
    root: context.root,
    keys: [...context.keys, key],
    inRequestHeaders:
      context.inRequestHeaders ||
      (context.root === "request" &&
        context.keys.length === 0 &&
        key === "headers"),
  };
}

function matchesAny(
  keys: readonly string[],
  set: ReadonlySet<string>,
): boolean {
  return keys.some((key) => set.has(normalizeKey(key)));
}

function isRedactionPermitted(context: RedactionContext): boolean {
  if (context.root === "request") {
    return (
      context.inRequestHeaders ||
      matchesAny(context.keys, CREDENTIAL_KEY_SET) ||
      matchesAny(context.keys, IDENTIFIER_KEY_SET)
    );
  }
  if (context.root === "billing") {
    return matchesAny(context.keys, IDENTIFIER_KEY_SET);
  }
  return false;
}

/**
 * The JSON pointer of the first redacted value that is not permitted, in a
 * deterministic walk: object keys in sorted order, arrays by index, strings
 * inside arrays included.
 */
function firstOffendingPointer(
  value: unknown,
  pointer: string,
  context: RedactionContext,
): string | null {
  if (typeof value === "string") {
    if (value.includes(REDACTED) && !isRedactionPermitted(context)) {
      return pointer;
    }
    return null;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = firstOffendingPointer(
        value[index],
        `${pointer}/${index}`,
        context,
      );
      if (found !== null) {
        return found;
      }
    }
    return null;
  }
  if (isRecord(value)) {
    for (const key of Object.keys(value).sort()) {
      const found = firstOffendingPointer(
        value[key],
        `${pointer}/${escapePointerSegment(key)}`,
        childContext(context, key),
      );
      if (found !== null) {
        return found;
      }
    }
  }
  return null;
}

/**
 * Redaction is permitted only under `request.headers`, at credential- or
 * identifier-named keys under `request`, and at identifier-named keys under
 * `billing`. A redacted value anywhere else is load-bearing.
 */
export function checkRedaction(receipt: unknown): ArtifactCheck {
  const pointer = firstOffendingPointer(receipt, "", ROOT_CONTEXT);
  if (pointer !== null) {
    return {
      ok: false,
      reason: "redacted_load_bearing",
      detail: `redacted value at ${pointer}`,
    };
  }
  return { ok: true };
}

/** `sha256:` plus the SHA-256 of the UTF-8 bytes of the RFC 8785 form. */
async function hashArtifact(value: unknown): Promise<string> {
  return `sha256:${await sha256Hex(canonicalize(value))}`;
}

/** The transcript artifact hash, or the refusal that stopped it. */
export async function transcriptArtifactHash(
  value: unknown,
): Promise<ArtifactHashResult> {
  const check = checkTranscriptArtifact(value);
  if (!check.ok) {
    return check;
  }
  return { ok: true, hash: await hashArtifact(value) };
}

/** The observation receipt artifact hash, or the refusal that stopped it. */
export async function receiptArtifactHash(
  value: unknown,
): Promise<ArtifactHashResult> {
  const check = checkReceiptArtifact(value);
  if (!check.ok) {
    return check;
  }
  return { ok: true, hash: await hashArtifact(value) };
}

/**
 * A failure report artifact is whichever kind its key set names: exactly the
 * transcript keys is a transcript, exactly the receipt keys is a receipt, and
 * anything else is neither.
 */
export function failureReportArtifactKind(value: unknown): ArtifactKind | null {
  if (!isRecord(value)) {
    return null;
  }
  if (keySetDetail(value, TRANSCRIPT_ARTIFACT_KEYS) === null) {
    return "transcript";
  }
  if (keySetDetail(value, RECEIPT_ARTIFACT_KEYS) === null) {
    return "receipt";
  }
  return null;
}

/** The failure report artifact hash, routed by key set. */
export async function failureReportArtifactHash(
  value: unknown,
): Promise<ArtifactHashResult> {
  const kind = failureReportArtifactKind(value);
  if (kind === "transcript") {
    return transcriptArtifactHash(value);
  }
  if (kind === "receipt") {
    return receiptArtifactHash(value);
  }
  return {
    ok: false,
    reason: "unknown_artifact",
    detail:
      "failure report artifact carries neither the transcript key set nor the receipt key set",
  };
}

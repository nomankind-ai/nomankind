import { canonicalize, sha256Hex } from "./hash.js";
import { extractHtml } from "./extract.js";

/**
 * Snapshot normalization and hashing under norm-v1.2 (decision D-012).
 *
 * Whitepaper section 4: the hash is taken over the page's extracted content,
 * normalized under a published, versioned rule, never over raw bytes. Steps 4
 * (normalizeText) and 5 (the hash) live here, together with the content-type
 * dispatch that decides which of them applies: HTML is extracted and
 * normalized, JSON is canonicalized under RFC 8785, plain text is normalized as
 * it is, and PDFs and other binaries are hashed over their raw bytes under
 * v1.2.
 *
 * WebCrypto only, through src/hash.ts, so the kernel runs unchanged on
 * Cloudflare Workers. Nothing here reads the clock or the network.
 */

/** The kinds of snapshot v1.2 knows how to hash. */
export type SnapshotKind = "html" | "json" | "pdf" | "text" | "binary";

/**
 * A hashed snapshot, or a refusal. `extracted` is the exact string the hash was
 * taken over for the text-bearing kinds, and null when the hash is over raw
 * bytes.
 */
export type SnapshotResult =
  | {
      ok: true;
      kind: SnapshotKind;
      hash: string;
      extracted: string | null;
    }
  | { ok: false; reason: "invalid_json" };

/** Every refusal snapshotHash can return. */
export const SNAPSHOT_REFUSALS = ["invalid_json"] as const;

/**
 * Step 4 of norm-v1.2, in order: NFC; CRLF and lone CR to LF; drop U+200B,
 * U+200C, U+200D and U+FEFF; collapse runs of spaces and tabs to one space;
 * strip leading and trailing spaces and tabs on each line; collapse three or
 * more newlines to two; trim the whole document.
 */
export function normalizeText(text: string): string {
  let out = text.normalize("NFC");
  out = out.replace(/\r\n?/gu, "\n");
  out = out.replace(/[\u200B\u200C\u200D\uFEFF]/gu, "");
  out = out.replace(/[ \t]+/gu, " ");
  out = out.replace(/^[ \t]+|[ \t]+$/gmu, "");
  out = out.replace(/\n{3,}/gu, "\n\n");
  return out.trim();
}

/** Step 5: SHA-256 over the UTF-8 bytes of the normalized text. */
export async function hashText(text: string): Promise<string> {
  return `sha256:${await sha256Hex(text)}`;
}

/**
 * The archive address of a stored body: SHA-256 over the raw bytes, unchanged
 * by any normalization. It is what a PDF or a binary hashes to under v1.2.
 */
export async function archiveAddress(bytes: Uint8Array): Promise<string> {
  return `sha256:${await sha256Hex(bytes)}`;
}

/**
 * The media type of a Content-Type header: the value before the first ";",
 * trimmed and ASCII-lowercased. null when absent, empty, or the placeholder
 * application/octet-stream, which tells us nothing and so calls for sniffing.
 */
export function mediaType(
  contentType: string | null | undefined,
): string | null {
  if (contentType === null || contentType === undefined) {
    return null;
  }
  const semicolon = contentType.indexOf(";");
  const raw = semicolon === -1 ? contentType : contentType.slice(0, semicolon);
  let value = "";
  for (const char of raw.trim()) {
    value += char >= "A" && char <= "Z" ? char.toLowerCase() : char;
  }
  if (value.length === 0 || value === "application/octet-stream") {
    return null;
  }
  return value;
}

/**
 * The sniff window: the number of leading bytes, after the BOM and leading
 * ASCII whitespace are skipped, that are searched for an HTML marker. Stated in
 * the norm-v1.2 document as part of the sniffing rule, so it moves only when
 * the rule version moves; it is not a policy number.
 */
export const SNIFF_WINDOW_BYTES = 1024;

const BOM = [0xef, 0xbb, 0xbf];
const ASCII_WHITESPACE = new Set([0x09, 0x0a, 0x0c, 0x0d, 0x20]);
const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46, 0x2d]; // "%PDF-"

const lenient = new TextDecoder("utf-8");

function decodeUtf8(bytes: Uint8Array): string {
  return lenient.decode(bytes);
}

function startsWithBytes(bytes: Uint8Array, prefix: readonly number[]): boolean {
  if (bytes.length < prefix.length) {
    return false;
  }
  return prefix.every((byte, index) => bytes[index] === byte);
}

/** Drop a UTF-8 BOM, then skip leading ASCII whitespace. */
function sniffStart(bytes: Uint8Array): Uint8Array {
  let start = startsWithBytes(bytes, BOM) ? BOM.length : 0;
  while (start < bytes.length && ASCII_WHITESPACE.has(bytes[start]!)) {
    start += 1;
  }
  return bytes.subarray(start);
}

function parsesAsJson(bytes: Uint8Array): boolean {
  try {
    JSON.parse(decodeUtf8(bytes));
    return true;
  } catch {
    return false;
  }
}

function decodesAsUtf8(bytes: Uint8Array): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * The kind of a body: from the media type when the server gave one, and by
 * sniffing the bytes when it did not.
 */
export function detectKind(
  bytes: Uint8Array,
  contentType: string | null | undefined,
): SnapshotKind {
  const type = mediaType(contentType);
  if (type !== null) {
    if (type === "text/html" || type === "application/xhtml+xml") {
      return "html";
    }
    const slash = type.indexOf("/");
    const subtype = slash === -1 ? "" : type.slice(slash + 1);
    if (
      type === "application/json" ||
      type === "text/json" ||
      subtype.endsWith("+json")
    ) {
      return "json";
    }
    if (type === "application/pdf") {
      return "pdf";
    }
    if (type.startsWith("text/")) {
      return "text";
    }
    return "binary";
  }

  const body = sniffStart(bytes);
  const head = decodeUtf8(body.subarray(0, SNIFF_WINDOW_BYTES)).toLowerCase();
  if (head.includes("<!doctype html") || head.includes("<html")) {
    return "html";
  }
  const first = body[0];
  if ((first === 0x7b || first === 0x5b) && parsesAsJson(body)) {
    return "json";
  }
  if (startsWithBytes(body, PDF_MAGIC)) {
    return "pdf";
  }
  if (decodesAsUtf8(bytes)) {
    return "text";
  }
  return "binary";
}

/**
 * Hash a snapshot body under norm-v1.2, dispatching on its kind: HTML is
 * extracted and normalized, JSON is canonicalized (steps 4 skipped), text is
 * normalized as it is, and a PDF or a binary hashes to its archive address.
 */
export async function snapshotHash(
  bytes: Uint8Array,
  contentType: string | null | undefined,
): Promise<SnapshotResult> {
  const kind = detectKind(bytes, contentType);

  if (kind === "html") {
    const extracted = normalizeText(extractHtml(decodeUtf8(bytes)));
    return { ok: true, kind, hash: await hashText(extracted), extracted };
  }

  if (kind === "json") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(decodeUtf8(bytes));
    } catch {
      return { ok: false, reason: "invalid_json" };
    }
    const extracted = canonicalize(parsed);
    return { ok: true, kind, hash: await hashText(extracted), extracted };
  }

  if (kind === "text") {
    const extracted = normalizeText(decodeUtf8(bytes));
    return { ok: true, kind, hash: await hashText(extracted), extracted };
  }

  return { ok: true, kind, hash: await archiveAddress(bytes), extracted: null };
}

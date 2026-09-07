import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  SNAPSHOT_REFUSALS,
  SNIFF_WINDOW_BYTES,
  archiveAddress,
  detectKind,
  hashText,
  mediaType,
  normalizeText,
  snapshotHash,
} from "../src/normalize.js";

/**
 * Steps 4 and 5 of snapshot normalization norm-v1.2, and the content-type
 * dispatch around them. Whitepaper section 4: two fetches of the same page that
 * differ only in a nonce, a timestamp or a per-visitor class must hash the
 * same, and a changed price must not.
 */

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const HTML_TYPE = "text/html; charset=utf-8";
const encoder = new TextEncoder();

function fixtureBytes(name: string): Uint8Array {
  return new Uint8Array(
    readFileSync(new URL(`./fixtures/html/${name}`, import.meta.url)),
  );
}

async function hashOf(name: string): Promise<string> {
  const result = await snapshotHash(fixtureBytes(name), HTML_TYPE);
  if (!result.ok) {
    throw new Error(`unexpected refusal: ${result.reason}`);
  }
  expect(result.kind).toBe("html");
  expect(result.hash).toMatch(HASH_PATTERN);
  return result.hash;
}

describe("normalizeText, step 4", () => {
  it("applies Unicode NFC first", () => {
    expect(normalizeText("e\u0301")).toBe("\u00E9");
    expect(normalizeText("e\u0301").length).toBe(1);
  });

  it("converts CRLF and a lone CR to LF", () => {
    expect(normalizeText("a\r\nb\rc")).toBe("a\nb\nc");
  });

  it("removes the zero-width characters and the BOM", () => {
    expect(normalizeText("a\u200Bb\u200Cc\u200Dd\uFEFFe")).toBe("abcde");
  });

  it("collapses runs of spaces and tabs to one space", () => {
    expect(normalizeText("a   b\t\tc \t d")).toBe("a b c d");
  });

  it("strips leading and trailing spaces and tabs on each line", () => {
    expect(normalizeText("x\n   a   \n\tb\t\ny")).toBe("x\na\nb\ny");
  });

  it("collapses three or more newlines to two", () => {
    expect(normalizeText("a\n\n\n\n\nb")).toBe("a\n\nb");
    expect(normalizeText("a\n\nb")).toBe("a\n\nb");
    expect(normalizeText("a\nb")).toBe("a\nb");
  });

  it("strips whitespace from the whole document", () => {
    expect(normalizeText("\n\n  a\n b \n\n ")).toBe("a\nb");
  });

  it("is idempotent, so a normalized page normalizes to itself", () => {
    const messy = "  \u00C9cole \t des  \r\n\r\n\r\n  mines \u200B ";
    const once = normalizeText(messy);
    expect(normalizeText(once)).toBe(once);
  });
});

describe("hashText and archiveAddress, step 5", () => {
  it("formats a hash as sha256 and sixty-four lowercase hex characters", async () => {
    const hash = await hashText("hello");
    expect(hash).toMatch(HASH_PATTERN);
    expect(hash).toBe(
      "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
  });

  it("hashes the raw bytes for an archive address", async () => {
    const bytes = encoder.encode("hello");
    expect(await archiveAddress(bytes)).toBe(await hashText("hello"));
  });

  it("names every refusal snapshotHash can return", () => {
    expect([...SNAPSHOT_REFUSALS]).toEqual(["invalid_json"]);
  });
});

describe("mediaType", () => {
  it("takes the value before the first semicolon, trimmed and lowercased", () => {
    expect(mediaType("Text/HTML; charset=UTF-8")).toBe("text/html");
    expect(mediaType("  application/json  ")).toBe("application/json");
  });

  it("returns null when it tells us nothing", () => {
    expect(mediaType(null)).toBeNull();
    expect(mediaType(undefined)).toBeNull();
    expect(mediaType("")).toBeNull();
    expect(mediaType("   ; charset=utf-8")).toBeNull();
    expect(mediaType("application/octet-stream")).toBeNull();
    expect(mediaType("APPLICATION/OCTET-STREAM; x=1")).toBeNull();
  });
});

describe("detectKind from the media type", () => {
  const bytes = encoder.encode("plain body");

  it("reads html, json, pdf, text and binary from the header", () => {
    expect(detectKind(bytes, "text/html")).toBe("html");
    expect(detectKind(bytes, "application/xhtml+xml")).toBe("html");
    expect(detectKind(bytes, "application/json")).toBe("json");
    expect(detectKind(bytes, "text/json")).toBe("json");
    expect(detectKind(bytes, "application/ld+json")).toBe("json");
    expect(detectKind(bytes, "application/pdf")).toBe("pdf");
    expect(detectKind(bytes, "text/plain; charset=utf-8")).toBe("text");
    expect(detectKind(bytes, "text/markdown")).toBe("text");
    expect(detectKind(bytes, "image/png")).toBe("binary");
    expect(detectKind(bytes, "application/zip")).toBe("binary");
  });
});

describe("detectKind by sniffing when the header tells us nothing", () => {
  const cases: ReadonlyArray<readonly [string, Uint8Array, string]> = [
    ["a doctype", encoder.encode("\n  <!DOCTYPE HTML><p>hi</p>"), "html"],
    ["an html tag", encoder.encode("<HTML lang='en'><p>hi</p></HTML>"), "html"],
    ["a bom then html", encoder.encode("\uFEFF<html><p>hi</p></html>"), "html"],
    ["an object", encoder.encode('  {"b": 1, "a": 2}'), "json"],
    ["an array", encoder.encode("[1, 2, 3]"), "json"],
    ["a pdf", encoder.encode("%PDF-1.7\n1 0 obj\n"), "pdf"],
    ["plain text", encoder.encode("Rate limits are per org.\n"), "text"],
    ["an unparseable object", encoder.encode("{not json"), "text"],
    ["invalid utf-8", new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00]), "binary"],
  ];

  for (const [label, bytes, kind] of cases) {
    it(`sniffs ${label} as ${kind}`, () => {
      expect(detectKind(bytes, null)).toBe(kind);
      expect(detectKind(bytes, undefined)).toBe(kind);
      expect(detectKind(bytes, "application/octet-stream")).toBe(kind);
    });
  }
});

describe("snapshotHash over HTML", () => {
  it("hashes a page and its nonce variant the same", async () => {
    expect(await hashOf("pricing-base.html")).toBe(
      await hashOf("pricing-nonce-variant.html"),
    );
    expect(await hashOf("model-card-base.html")).toBe(
      await hashOf("model-card-nonce-variant.html"),
    );
  });

  it("hashes a changed price differently", async () => {
    expect(await hashOf("pricing-base.html")).not.toBe(
      await hashOf("pricing-price-variant.html"),
    );
  });

  it("returns the normalized text it hashed", async () => {
    const result = await snapshotHash(
      fixtureBytes("pricing-base.html"),
      HTML_TYPE,
    );
    if (!result.ok) {
      throw new Error(`unexpected refusal: ${result.reason}`);
    }
    expect(result.extracted).not.toBeNull();
    expect(result.extracted).toBe(normalizeText(result.extracted!));
    expect(result.extracted).toContain("$20 per seat per month");
    expect(result.extracted).not.toContain("Northwind status");
    expect(result.extracted).not.toContain("nonce");
    expect(result.extracted).not.toContain("Page generated");
    expect(result.hash).toBe(await hashText(result.extracted!));
  });
});

describe("snapshotHash over JSON", () => {
  const json = '{"model":"kestrel-2","price_cents":2000,"tiers":[1,2]}';
  const reordered =
    '{\n  "tiers": [1, 2],\n  "price_cents": 2000,\n  "model": "kestrel-2"\n}\n';
  const changed = '{"model":"kestrel-2","price_cents":2500,"tiers":[1,2]}';

  it("hashes the same document the same through whitespace and key order", async () => {
    const first = await snapshotHash(encoder.encode(json), "application/json");
    const second = await snapshotHash(
      encoder.encode(reordered),
      "application/json",
    );
    if (!first.ok || !second.ok) {
      throw new Error("unexpected refusal");
    }
    expect(first.kind).toBe("json");
    expect(first.hash).toMatch(HASH_PATTERN);
    expect(first.hash).toBe(second.hash);
    expect(first.extracted).toBe(
      '{"model":"kestrel-2","price_cents":2000,"tiers":[1,2]}',
    );
  });

  it("hashes a changed value differently", async () => {
    const first = await snapshotHash(encoder.encode(json), "application/json");
    const other = await snapshotHash(
      encoder.encode(changed),
      "application/json",
    );
    if (!first.ok || !other.ok) {
      throw new Error("unexpected refusal");
    }
    expect(first.hash).not.toBe(other.hash);
  });

  it("refuses a body that does not parse", async () => {
    const result = await snapshotHash(
      encoder.encode('{"model": '),
      "application/json",
    );
    expect(result).toEqual({ ok: false, reason: "invalid_json" });
  });
});

describe("snapshotHash over text, PDFs and binaries", () => {
  it("normalizes plain text before hashing it", async () => {
    const source = "  Rate limits \t\r\n\r\n\r\n\r\n  are per org.  ";
    const result = await snapshotHash(
      encoder.encode(source),
      "text/plain; charset=utf-8",
    );
    if (!result.ok) {
      throw new Error(`unexpected refusal: ${result.reason}`);
    }
    expect(result.kind).toBe("text");
    expect(result.extracted).toBe("Rate limits\n\nare per org.");
    expect(result.hash).toBe(await hashText("Rate limits\n\nare per org."));
  });

  it("hashes a PDF over its raw bytes and extracts nothing", async () => {
    const bytes = encoder.encode("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\n");
    const result = await snapshotHash(bytes, "application/pdf");
    if (!result.ok) {
      throw new Error(`unexpected refusal: ${result.reason}`);
    }
    expect(result.kind).toBe("pdf");
    expect(result.extracted).toBeNull();
    expect(result.hash).toBe(await archiveAddress(bytes));
    expect(result.hash).toMatch(HASH_PATTERN);
  });

  it("hashes a binary over its raw bytes and extracts nothing", async () => {
    const bytes = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
    const result = await snapshotHash(bytes, "image/jpeg");
    if (!result.ok) {
      throw new Error(`unexpected refusal: ${result.reason}`);
    }
    expect(result.kind).toBe("binary");
    expect(result.extracted).toBeNull();
    expect(result.hash).toBe(await archiveAddress(bytes));
  });

  it("hashes the same bytes the same whichever binary type they carry", async () => {
    const bytes = new Uint8Array([0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff]);
    const first = await snapshotHash(bytes, "image/png");
    const second = await snapshotHash(bytes, null);
    if (!first.ok || !second.ok) {
      throw new Error("unexpected refusal");
    }
    expect(first.hash).toBe(second.hash);
    expect(second.kind).toBe("binary");
  });
});

describe("the sniff window", () => {
  it("is the 1024 bytes the norm-v1.2 document states", () => {
    expect(SNIFF_WINDOW_BYTES).toBe(1024);
  });

  it("sniffs html when the marker ends inside the window", () => {
    const marker = "<html>";
    const padding = "x".repeat(SNIFF_WINDOW_BYTES - marker.length);
    const bytes = encoder.encode(`${padding}${marker}<p>a price</p>`);
    expect(bytes.length).toBeGreaterThan(SNIFF_WINDOW_BYTES);
    expect(detectKind(bytes, null)).toBe("html");
  });

  it("sniffs text when the marker starts at the window boundary", () => {
    const padding = "x".repeat(SNIFF_WINDOW_BYTES);
    const bytes = encoder.encode(`${padding}<html><p>a price</p>`);
    expect(detectKind(bytes, null)).toBe("text");
  });
});

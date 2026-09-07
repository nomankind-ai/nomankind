import { describe, expect, it } from "vitest";

import {
  base64Decode,
  base64Encode,
  base64urlDecode,
  base64urlEncode,
} from "../src/encoding.js";

const LENGTHS = [0, 1, 2, 3, 32, 64];

function bytesOfLength(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = (index * 37 + 11) % 256;
  }
  return bytes;
}

/** The URL-safe substitution the RFC 4648 section 5 alphabet is defined by. */
function urlSafe(standard: string): string {
  return standard.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

describe("base64url", () => {
  it.each(LENGTHS)("round-trips %i bytes", (length) => {
    const bytes = bytesOfLength(length);
    const decoded = base64urlDecode(base64urlEncode(bytes));
    expect(Array.from(decoded)).toEqual(Array.from(bytes));
  });

  it.each(LENGTHS)(
    "matches standard base64 after the URL-safe substitution for %i bytes",
    (length) => {
      const bytes = bytesOfLength(length);
      expect(base64urlEncode(bytes)).toBe(urlSafe(base64Encode(bytes)));
    },
  );

  it("never emits padding", () => {
    for (const length of LENGTHS) {
      expect(base64urlEncode(bytesOfLength(length))).not.toContain("=");
    }
  });

  it("produces only URL-safe characters for bytes that force + and /", () => {
    // 0xfb 0xef 0xbe encodes as "++++" in the standard alphabet's territory.
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf, 0xff]);
    const encoded = base64urlEncode(bytes);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Array.from(base64urlDecode(encoded))).toEqual(Array.from(bytes));
  });

  it("rejects padded input", () => {
    expect(() => base64urlDecode("AA==")).toThrow();
  });

  it("rejects the standard alphabet's + and /", () => {
    expect(() => base64urlDecode("+" + "AAA")).toThrow();
    expect(() => base64urlDecode("/" + "AAA")).toThrow();
  });

  it("rejects an impossible length", () => {
    expect(() => base64urlDecode("A")).toThrow();
    expect(() => base64urlDecode("AAAAA")).toThrow();
  });

  it("rejects characters outside the alphabet", () => {
    expect(() => base64urlDecode("AA A")).toThrow();
    expect(() => base64urlDecode("AA!A")).toThrow();
  });

  it("decodes the empty string to no bytes", () => {
    expect(base64urlDecode("").length).toBe(0);
  });
});

describe("standard base64", () => {
  it.each(LENGTHS)("round-trips %i bytes", (length) => {
    const bytes = bytesOfLength(length);
    const decoded = base64Decode(base64Encode(bytes));
    expect(Array.from(decoded)).toEqual(Array.from(bytes));
  });

  it("pads to a multiple of four", () => {
    for (const length of LENGTHS) {
      expect(base64Encode(bytesOfLength(length)).length % 4).toBe(0);
    }
  });

  it("rejects unpadded and malformed input", () => {
    expect(() => base64Decode("AA")).toThrow();
    expect(() => base64Decode("=")).toThrow();
    expect(() => base64Decode("A=AA")).toThrow();
    expect(() => base64Decode("AA-A")).toThrow();
  });
});

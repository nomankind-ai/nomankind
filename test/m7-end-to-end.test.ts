import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  NORM_VERSION,
  archiveAddress,
  buildTranscriptArtifact,
  detectKind,
  receiptArtifactHash,
  snapshotHash,
  transcriptArtifactHash,
} from "../src/index.js";

import entrySchema from "../schema/nomankind-entry-schema.json";

/**
 * M7 end to end, through the package's public surface only: everything this
 * milestone added is reachable from `src/index.ts`, and the pieces compose as
 * the norm-v1.2 document says. Whitepaper section 4: a nonce must not move a
 * hash, a price must, and a redaction may never stand where the test predicate
 * reads.
 */

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const HTML_TYPE = "text/html; charset=utf-8";
const encoder = new TextEncoder();

function fixtureBytes(name: string): Uint8Array {
  return new Uint8Array(
    readFileSync(new URL(`./fixtures/html/${name}`, import.meta.url)),
  );
}

async function hashOf(
  bytes: Uint8Array,
  contentType: string | null,
): Promise<string> {
  const result = await snapshotHash(bytes, contentType);
  if (!result.ok) {
    throw new Error(`unexpected refusal: ${result.reason}`);
  }
  expect(result.hash).toMatch(HASH_PATTERN);
  return result.hash;
}

describe("M7 end to end: snapshots through the package surface", () => {
  it("hashes a page and its nonce variant the same, and its price variant differently", async () => {
    const base = await hashOf(fixtureBytes("pricing-base.html"), HTML_TYPE);
    const nonce = await hashOf(
      fixtureBytes("pricing-nonce-variant.html"),
      HTML_TYPE,
    );
    const price = await hashOf(
      fixtureBytes("pricing-price-variant.html"),
      HTML_TYPE,
    );

    expect(nonce).toBe(base);
    expect(price).not.toBe(base);
  });

  it("sniffs the same page as html with no content type and hashes it the same", async () => {
    const bytes = fixtureBytes("pricing-base.html");
    expect(detectKind(bytes, null)).toBe("html");
    expect(await hashOf(bytes, null)).toBe(await hashOf(bytes, HTML_TYPE));
  });

  it("hashes a JSON body the same across whitespace and key order", async () => {
    const compact = encoder.encode('{"limit":100,"model":"example-model-1"}');
    const spaced = encoder.encode(
      '{\n  "model" : "example-model-1",\n  "limit" : 100\n}\n',
    );
    expect(await hashOf(spaced, "application/json")).toBe(
      await hashOf(compact, "application/json"),
    );
  });

  it("hashes a PDF and a binary to their archive addresses", async () => {
    const pdf = encoder.encode("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\n");
    expect(await hashOf(pdf, "application/pdf")).toBe(
      await archiveAddress(pdf),
    );

    const binary = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0xff]);
    expect(await hashOf(binary, "image/png")).toBe(
      await archiveAddress(binary),
    );
  });
});

/** Shaped exactly like the schema's `evidence`, citation included. */
const EVIDENCE = {
  model: "example-model-1",
  prompt: "State the price of one metered call.",
  parameters: { temperature: 0, max_tokens: 64 },
  output: "the submitter's own output",
  predicate: "the output states a price of 0.002 per call",
  observed_at: "2026-09-07T09:00:00Z",
  provider_statement: "https://example.com/pricing",
};

async function transcriptHashOf(value: unknown): Promise<string> {
  const result = await transcriptArtifactHash(value);
  if (!result.ok) {
    throw new Error(`unexpected refusal: ${result.reason} ${result.detail}`);
  }
  expect(result.hash).toMatch(HASH_PATTERN);
  return result.hash;
}

describe("M7 end to end: artifacts through the package surface", () => {
  it("hashes a transcript built from the entry's evidence", async () => {
    const artifact = buildTranscriptArtifact(
      EVIDENCE,
      "the run's output",
      "2026-09-07T12:00:00Z",
    );
    expect(Object.keys(artifact).sort()).toEqual([
      "model",
      "observed_at",
      "output",
      "parameters",
      "predicate",
      "prompt",
    ]);
    await transcriptHashOf(artifact);
  });

  it("moves the transcript hash when a parameter moves", async () => {
    const base = await transcriptHashOf(
      buildTranscriptArtifact(EVIDENCE, "out", "2026-09-07T12:00:00Z"),
    );
    const changed = await transcriptHashOf(
      buildTranscriptArtifact(
        { ...EVIDENCE, parameters: { temperature: 1, max_tokens: 64 } },
        "out",
        "2026-09-07T12:00:00Z",
      ),
    );
    expect(changed).not.toBe(base);
  });

  it("hashes a transcript independently of key order", async () => {
    const artifact = buildTranscriptArtifact(
      EVIDENCE,
      "out",
      "2026-09-07T12:00:00Z",
    );
    const reordered = {
      observed_at: artifact.observed_at,
      predicate: artifact.predicate,
      output: artifact.output,
      parameters: { max_tokens: 64, temperature: 0 },
      prompt: artifact.prompt,
      model: artifact.model,
    };
    expect(await transcriptHashOf(reordered)).toBe(
      await transcriptHashOf(artifact),
    );
  });

  it("hashes a receipt whose credential is redacted and refuses one whose price is", async () => {
    const receipt = {
      method: "metered_call",
      subject: "did:key:zProviderUnderTest",
      test: "the metered call is billed at 0.002",
      request: {
        url: "https://api.example.com/v1/complete",
        headers: {
          authorization: "[REDACTED]",
          "content-type": "application/json",
        },
        body: { model: "example-model-1", max_tokens: 16 },
      },
      response: {
        status: 200,
        headers: { "content-type": "application/json" },
        body: { price: "0.002" },
      },
      billing: { account_id: "[REDACTED]", amount: "0.002", currency: "USD" },
      observed_at: "2026-09-07T12:00:00Z",
      observer: "did:key:zObserver",
    };

    const accepted = await receiptArtifactHash(receipt);
    expect(accepted.ok).toBe(true);
    expect(accepted.ok && accepted.hash).toMatch(HASH_PATTERN);

    const loadBearing = await receiptArtifactHash({
      ...receipt,
      response: {
        ...receipt.response,
        body: { price: "[REDACTED]" },
      },
    });
    expect(loadBearing.ok).toBe(false);
    expect(loadBearing.ok === false && loadBearing.reason).toBe(
      "redacted_load_bearing",
    );
  });
});

describe("M7 end to end: the norm version the kernel writes", () => {
  it("is norm-v1.2 and satisfies the schema's pattern", () => {
    expect(NORM_VERSION).toBe("norm-v1.2");
    const pattern = new RegExp(
      entrySchema.properties.norm_version.pattern,
      "u",
    );
    expect(pattern.test(NORM_VERSION)).toBe(true);
  });

  it("leaves the shipped example entry on the version it was sealed under", () => {
    const example = JSON.parse(
      readFileSync(
        new URL("../schema/nomankind-entry-example.json", import.meta.url),
        "utf8",
      ),
    ) as { norm_version: string };
    expect(example.norm_version).toBe("norm-v1.1");
  });
});

import { describe, expect, it } from "vitest";

import {
  ARTIFACT_REFUSALS,
  CREDENTIAL_KEYS,
  IDENTIFIER_KEYS,
  RECEIPT_ARTIFACT_KEYS,
  REDACTED,
  TRANSCRIPT_ARTIFACT_KEYS,
  buildTranscriptArtifact,
  checkRedaction,
  checkReceiptArtifact,
  checkTranscriptArtifact,
  failureReportArtifactHash,
  failureReportArtifactKind,
  receiptArtifactHash,
  transcriptArtifactHash,
} from "../src/artifact.js";

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;

const EVIDENCE = {
  model: "example-model-1",
  prompt: "State the price of the metered endpoint.",
  parameters: { temperature: 0, max_tokens: 64 },
  output: "the submitter's own output",
  predicate: "the output states a price of 0.002 per call",
  observed_at: "2026-09-07T09:00:00Z",
  provider_statement: "https://example.com/pricing",
};

function transcript(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    model: EVIDENCE.model,
    prompt: EVIDENCE.prompt,
    parameters: EVIDENCE.parameters,
    output: "the run's output",
    predicate: EVIDENCE.predicate,
    observed_at: "2026-09-07T12:00:00Z",
    ...overrides,
  };
}

function receipt(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    method: "metered_call",
    subject: "did:key:zProviderUnderTest",
    test: "the metered call returns HTTP 402 with error code quota_exceeded",
    request: {
      url: "https://api.example.com/v1/complete",
      headers: {
        authorization: REDACTED,
        "content-type": "application/json",
      },
      body: { model: "example-model-1", max_tokens: 16 },
    },
    response: {
      status: 402,
      headers: { "content-type": "application/json" },
      body: { error: "quota_exceeded", price: "0.002" },
    },
    billing: { account_id: REDACTED, amount: "0.00", currency: "USD" },
    observed_at: "2026-09-07T12:00:00Z",
    observer: "did:key:zObserver",
    ...overrides,
  };
}

async function hashOf(value: unknown): Promise<string> {
  const result = await transcriptArtifactHash(value);
  if (!result.ok) {
    throw new Error(`unexpected refusal: ${result.reason} ${result.detail}`);
  }
  expect(result.hash).toMatch(HASH_PATTERN);
  return result.hash;
}

async function receiptHashOf(value: unknown): Promise<string> {
  const result = await receiptArtifactHash(value);
  if (!result.ok) {
    throw new Error(`unexpected refusal: ${result.reason} ${result.detail}`);
  }
  expect(result.hash).toMatch(HASH_PATTERN);
  return result.hash;
}

describe("transcript artifacts", () => {
  it("hashes independently of key order", async () => {
    const inOrder = transcript();
    const shuffled: Record<string, unknown> = {
      observed_at: inOrder["observed_at"],
      predicate: inOrder["predicate"],
      model: inOrder["model"],
      output: inOrder["output"],
      parameters: inOrder["parameters"],
      prompt: inOrder["prompt"],
    };
    expect(Object.keys(shuffled)).not.toEqual(Object.keys(inOrder));
    expect(await hashOf(shuffled)).toBe(await hashOf(inOrder));
  });

  it("changes when parameters change", async () => {
    const changed = transcript({ parameters: { temperature: 1, max_tokens: 64 } });
    expect(await hashOf(changed)).not.toBe(await hashOf(transcript()));
  });

  it("refuses a missing key, naming it", async () => {
    const missing = transcript();
    delete missing["predicate"];
    const result = await transcriptArtifactHash(missing);
    expect(result).toEqual({
      ok: false,
      reason: "transcript_shape",
      detail: 'missing key "predicate"',
    });
  });

  it("refuses an extra key, naming it", () => {
    const extra = transcript({
      provider_statement: EVIDENCE.provider_statement,
    });
    expect(checkTranscriptArtifact(extra)).toEqual({
      ok: false,
      reason: "transcript_shape",
      detail: 'unexpected key "provider_statement"',
    });
  });

  it("refuses a value that is not a JSON object", () => {
    const result = checkTranscriptArtifact(["model"]);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("transcript_shape");
  });

  it("builds from evidence, copying four fields and never the citation", () => {
    const built = buildTranscriptArtifact(
      EVIDENCE,
      "the runner's output",
      "2026-09-07T13:30:00Z",
    );
    expect(Object.keys(built).sort()).toEqual([...TRANSCRIPT_ARTIFACT_KEYS].sort());
    expect(built.model).toBe(EVIDENCE.model);
    expect(built.prompt).toBe(EVIDENCE.prompt);
    expect(built.parameters).toBe(EVIDENCE.parameters);
    expect(built.predicate).toBe(EVIDENCE.predicate);
    expect(built.output).toBe("the runner's output");
    expect(built.observed_at).toBe("2026-09-07T13:30:00Z");
    expect(built).not.toHaveProperty("provider_statement");
    expect(checkTranscriptArtifact(built).ok).toBe(true);
  });
});

describe("observation receipt artifacts", () => {
  it("hashes independently of key order", async () => {
    const inOrder = receipt();
    const shuffled: Record<string, unknown> = {};
    for (const key of [...RECEIPT_ARTIFACT_KEYS].reverse()) {
      shuffled[key] = inOrder[key];
    }
    expect(Object.keys(shuffled)).not.toEqual(Object.keys(inOrder));
    expect(await receiptHashOf(shuffled)).toBe(await receiptHashOf(inOrder));
  });

  it("refuses an unknown method", () => {
    expect(checkReceiptArtifact(receipt({ method: "screenshot" }))).toEqual({
      ok: false,
      reason: "unknown_method",
      detail:
        'method "screenshot" is not one of metered_call, probe_to_limit, endpoint_error, completed_request, other',
    });
  });

  it("refuses a metered call with no billing line", () => {
    const result = checkReceiptArtifact(receipt({ billing: null }));
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("billing_shape");
  });

  it("refuses a non-metered method that carries a billing line", () => {
    const result = checkReceiptArtifact(receipt({ method: "endpoint_error" }));
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("billing_shape");
  });

  it("accepts a non-metered method with a null billing line", async () => {
    const hash = await receiptHashOf(
      receipt({ method: "endpoint_error", billing: null }),
    );
    expect(hash).toMatch(HASH_PATTERN);
  });

  it("refuses a missing key and an extra key, naming them", () => {
    const missing = receipt();
    delete missing["observer"];
    expect(checkReceiptArtifact(missing)).toEqual({
      ok: false,
      reason: "receipt_shape",
      detail: 'missing key "observer"',
    });
    expect(checkReceiptArtifact(receipt({ notes: "extra" }))).toEqual({
      ok: false,
      reason: "receipt_shape",
      detail: 'unexpected key "notes"',
    });
  });
});

describe("redaction", () => {
  it("permits an authorization header", () => {
    expect(checkRedaction(receipt())).toEqual({ ok: true });
  });

  it("permits a nested value under request.headers", () => {
    const permitted = receipt({
      request: {
        url: "https://api.example.com/v1/complete",
        headers: { forwarded: { by: REDACTED } },
        body: {},
      },
    });
    expect(checkRedaction(permitted)).toEqual({ ok: true });
  });

  it("permits a value under request whose own key is a credential key", () => {
    const permitted = receipt({
      request: {
        url: { template: "https://api.example.com/v1/complete", params: { api_key: REDACTED } },
        headers: {},
        body: {},
      },
    });
    expect(checkRedaction(permitted)).toEqual({ ok: true });
  });

  it("permits an identifier under billing", () => {
    const permitted = receipt({
      billing: { account_id: REDACTED, amount: "0.002" },
    });
    expect(checkRedaction(permitted)).toEqual({ ok: true });
  });

  it("matches keys case-insensitively and across - and _", () => {
    const permitted = receipt({
      request: {
        url: "https://api.example.com/v1/complete",
        headers: {},
        body: { "X-Api-Key": REDACTED, Api_Key: REDACTED },
      },
    });
    expect(checkRedaction(permitted)).toEqual({ ok: true });
  });

  it("permits a redacted string inside an array under a credential key", () => {
    const permitted = receipt({
      request: {
        url: "https://api.example.com/v1/complete",
        headers: {},
        body: { token: [REDACTED, REDACTED] },
      },
    });
    expect(checkRedaction(permitted)).toEqual({ ok: true });
  });

  it.each([
    [
      "a price in the response body",
      receipt({
        response: {
          status: 402,
          headers: {},
          body: { error: "quota_exceeded", price: REDACTED },
        },
      }),
      "/response/body/price",
    ],
    [
      "a response status",
      receipt({
        response: { status: REDACTED, headers: {}, body: {} },
      }),
      "/response/status",
    ],
    [
      "a billing amount",
      receipt({ billing: { account_id: REDACTED, amount: REDACTED } }),
      "/billing/amount",
    ],
    [
      "a model identifier in the request body",
      receipt({
        request: {
          url: "https://api.example.com/v1/complete",
          headers: { authorization: REDACTED },
          body: { model: REDACTED },
        },
      }),
      "/request/body/model",
    ],
    ["the subject", receipt({ subject: REDACTED }), "/subject"],
    [
      "a string inside an array under response",
      receipt({
        response: { status: 402, headers: {}, body: { errors: ["ok", REDACTED] } },
      }),
      "/response/body/errors/1",
    ],
  ])("refuses %s", (_name, value, pointer) => {
    expect(checkRedaction(value)).toEqual({
      ok: false,
      reason: "redacted_load_bearing",
      detail: `redacted value at ${pointer}`,
    });
    expect(checkReceiptArtifact(value)).toEqual({
      ok: false,
      reason: "redacted_load_bearing",
      detail: `redacted value at ${pointer}`,
    });
  });

  it("reports the first offender in a deterministic walk", () => {
    const twoOffenders = receipt({
      subject: REDACTED,
      response: { status: REDACTED, headers: {}, body: {} },
    });
    expect(checkRedaction(twoOffenders)).toEqual({
      ok: false,
      reason: "redacted_load_bearing",
      detail: "redacted value at /response/status",
    });
  });
});

describe("failure report artifacts", () => {
  it("routes by key set", async () => {
    expect(failureReportArtifactKind(transcript())).toBe("transcript");
    expect(failureReportArtifactKind(receipt())).toBe("receipt");
    expect(failureReportArtifactKind({ note: "neither" })).toBeNull();

    const asTranscript = await failureReportArtifactHash(transcript());
    expect(asTranscript).toEqual(await transcriptArtifactHash(transcript()));

    const asReceipt = await failureReportArtifactHash(receipt());
    expect(asReceipt).toEqual(await receiptArtifactHash(receipt()));

    expect(asTranscript.ok && asTranscript.hash).toMatch(HASH_PATTERN);
    expect(asReceipt.ok && asReceipt.hash).toMatch(HASH_PATTERN);
  });

  it("refuses an artifact of neither kind", async () => {
    const result = await failureReportArtifactHash({ note: "neither" });
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toBe("unknown_artifact");
    expect(ARTIFACT_REFUSALS).toContain("unknown_artifact");
  });
});

describe("the redaction key sets", () => {
  /**
   * Pinned exactly, in the folded form the code compares in: ASCII-lowercased
   * with `-` written as `_`. The document's `proxy-authorization`,
   * `set-cookie`, and `x-api-key` fold to underscores, and its `api-key` folds
   * onto `api_key`. Adding or removing a key fails here.
   */
  it("pins the credential keys", () => {
    expect([...CREDENTIAL_KEYS]).toEqual([
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
  });

  it("pins the identifier keys", () => {
    expect([...IDENTIFIER_KEYS]).toEqual([
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
  });

  it("permits redaction at every credential and identifier key under request", () => {
    for (const key of [...CREDENTIAL_KEYS, ...IDENTIFIER_KEYS]) {
      const value = receipt({
        request: { url: "https://example.com/v1/price", [key]: REDACTED },
      });
      expect(checkRedaction(value)).toEqual({ ok: true });
    }
  });

  it("permits redaction at every identifier key under billing", () => {
    for (const key of IDENTIFIER_KEYS) {
      const value = receipt({
        method: "metered_call",
        billing: { amount: "0.002", currency: "USD", [key]: REDACTED },
      });
      expect(checkRedaction(value)).toEqual({ ok: true });
    }
  });
});

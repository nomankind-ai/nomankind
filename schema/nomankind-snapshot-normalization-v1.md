# Snapshot Normalization Rule — norm-v1.1

The published, versioned rule the whitepaper (v1.5) and entry schema (v0.6) reference. `snapshot_hash`, `receipt_hash`, and `artifact_hash` are computed by this rule, never over raw bytes. Which version applies is fixed per entry: the entry's `norm_version` names the version in force at its `submitted_at`, and every later hash on that entry (validators, reconfirmers, challengers, failure reporters) uses the same version. norm-v1.1 applies to entries submitted on or after 2026-09-03 and supersedes norm-v1 (which applied from 2026-09-01; no entries were sealed under it). New versions apply to new entries only, never retroactively.

## Pipeline

1. **Fetch.** One HTTP GET, no JavaScript execution, no cookies, no authentication. Fixed request headers: `User-Agent: nomankind-snapshot/1 (+https://nomankind.ai/norm)`, `Accept: text/html,application/json,application/pdf,text/plain;q=0.9,*/*;q=0.5`, `Accept-Language: en`, `Accept-Encoding: identity`. Follow up to five redirects; the final URL is recorded in the sidecar. Timeout thirty seconds. A page that needs JavaScript to show its content is a source this rule cannot pin; the submitter must cite a static representation instead (the provider's API, a PDF, a plain-text or JSON endpoint, or the archive URI of a receipt). Rendered captures are out of scope for norm-v1.x and will be a later version if needed.

2. **Archive.** Store the raw response body in the content-addressed snapshot archive at `sha256` of the body bytes. Store a sidecar at `<hash>.meta.json` with `{final_url, status, headers, fetched_at, fetcher}` where `fetcher` is the 1F916 identity that fetched. The raw capture is evidence and is never what `snapshot_hash` hashes.

3. **Extract by content type** (from the Content-Type header, falling back to sniffing):
   - **HTML/XHTML:** extract main readable content to plain text using the pinned reference extractor (trafilatura, version pinned in the repo, `output_format="txt"`, `include_comments=False`, `include_tables=True`, `include_links=False`). The pinned extractor version is part of this rule; upgrading it means issuing a new norm version.
   - **JSON:** canonicalize per RFC 8785 (JCS). The canonical bytes are the extracted content; skip step 4.
   - **PDF:** extract text with pinned `pdftotext -layout` (poppler version pinned in the repo).
   - **Plain text / markdown:** use as-is.
   - **Any other type (images, binaries):** no extraction; `snapshot_hash` is over the raw bytes, same value as the archive address.

4. **Normalize text.** In order: decode to Unicode, apply NFC; convert CRLF and CR to LF; remove zero-width and BOM characters (U+200B–U+200D, U+FEFF); collapse runs of spaces and tabs to a single space; strip trailing whitespace on each line; collapse three or more consecutive newlines to two; strip leading and trailing whitespace from the whole document.

5. **Hash.** Encode the result as UTF-8 and compute SHA-256. Format: `sha256:<64 lowercase hex>`.

## Transcript artifacts (behavior and misbehavior entries)

The artifact is a JSON object with exactly these keys and no others: `model`, `prompt`, `parameters`, `output`, `predicate`, `observed_at`. These are the entry's `evidence` fields minus `provider_statement`, which is a citation and not part of the measurement. Its hash is SHA-256 over the RFC 8785 canonical form of that object. A validator's reproduction transcript and a reconfirmer's re-run transcript use the same key set with the runner's own `output` and `observed_at`; `model`, `prompt`, `parameters`, and `predicate` are copied from the entry unchanged.

## Observation receipt artifacts (observed entries outside behavior and misbehavior)

An observed entry carries `observation.receipt_hash`; each approving validator and each reconfirmer carries its own receipt hash. The receipt is a JSON object with exactly these keys: `method` (same enum as the schema), `subject`, `test` (copied from the entry's `observation.test`), `request` (the exact request made, after redaction), `response` (status, the headers the test names, body), `billing` (for `metered_call`: the provider's billing line as returned or exported, after redaction; `null` otherwise), `observed_at`, and `observer` (1F916 identity). Its hash is SHA-256 over the RFC 8785 canonical form. The raw receipt object is stored in the snapshot archive at that hash.

Redaction is part of the rule. The placeholder string is `"[REDACTED]"`. It may replace: authorization headers, API keys and tokens, and account, organization, project, and billing-account identifiers that the claim does not depend on. It may not replace anything the `test` predicate reads (status codes, error codes, prices, limits, model identifiers, counts). Redacting a load-bearing value invalidates the receipt and is a rejection reason.

## Failure report artifacts

A `failure_reports[].artifact_hash` is computed exactly like an observation receipt when the failure is a request/response, and exactly like a transcript artifact when it is a model interaction.

## Mismatch semantics

Hashes are receipts, not gates. A validator whose hash differs from the submitter's is not an automatic rejection: pages differ between viewers, and two honest measurements return two different receipts by nature. Each signature records what its signer saw; the validator's signed judgment that the source or the measurement says what the entry says is the attestation. Matching hashes for an unchanged page are the expected case because a fixed fetch plus extraction plus normalization removes nonces, timestamps, and per-visitor markup; matching hashes for observation receipts are not expected and carry no meaning.

## Reference implementation

`normalize.py` in the code repository, with exact dependency versions pinned, is the executable form of this rule. Where the script and this document disagree, this document governs and the script gets fixed. The TypeScript PoC ships a reduced extractor for HTML fixtures (steps 4 and 5 exact, step 3 approximated); hashes it produces are for the PoC only and the deviation is logged in `docs/GAPS.md`.

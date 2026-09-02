# Snapshot Normalization Rule — norm-v1

The published, versioned rule the whitepaper and entry schema (v0.5) reference. `snapshot_hash`, `receipt_hash`, and `artifact_hash` are computed by this rule, never over raw bytes. Which version applies to an entry is determined by its `submitted_at` against this policy: norm-v1 applies to all entries submitted on or after 2026-09-01. New versions apply to new entries only, never retroactively.

## Pipeline

1. **Fetch and archive.** Fetch the source. Store the raw capture (exact bytes plus response headers) in the content-addressed snapshot archive; its address is `sha256` of the raw bytes. The raw capture is evidence and is never what `snapshot_hash` hashes.

2. **Extract by content type** (from the Content-Type header, falling back to sniffing):
   - **HTML/XHTML:** extract main readable content to plain text using the pinned reference extractor (trafilatura, version pinned in the repo, `output_format="txt"`, `include_comments=False`, `include_tables=True`). The pinned extractor version is part of this rule; upgrading it means issuing norm-v2.
   - **JSON:** canonicalize per RFC 8785 (JCS). The canonical bytes are the extracted content; skip step 3.
   - **PDF:** extract text with pinned `pdftotext -layout` (poppler version pinned in the repo).
   - **Plain text / markdown:** use as-is.
   - **Any other type (images, binaries):** no extraction; `snapshot_hash` is over the raw bytes, same value as the archive address.

3. **Normalize text.** In order: decode to Unicode, apply NFC; convert CRLF and CR to LF; remove zero-width and BOM characters (U+200B–U+200D, U+FEFF); collapse runs of spaces and tabs to a single space; strip trailing whitespace on each line; collapse three or more consecutive newlines to two; strip leading and trailing whitespace from the whole document.

4. **Hash.** Encode the result as UTF-8 and compute SHA-256. Format: `sha256:<64 lowercase hex>`.

## Transcript artifacts (behavior and misbehavior entries)

The artifact is a JSON object with the entry's evidence fields (model, prompt, output, observed_at). Its hash is SHA-256 over the RFC 8785 canonical form of that object. The same applies to a validator's reproduction transcript and a reconfirmer's re-run transcript.

## Observation receipt artifacts (observed entries, whitepaper Section 8)

An observed entry outside behavior/misbehavior carries `observation.receipt_hash`; each approving validator carries its own `approvers[].observation.receipt_hash`. The receipt is a JSON object with: `method` (same enum as the schema), `subject`, `request` (the exact request made, with secrets redacted to a fixed placeholder before hashing), `response` (status, headers relevant to the claim, body), `billing` (for `metered_call`: the provider's billing line as returned or exported, verbatim), `observed_at`, and `observer` (1F916 identity). Its hash is SHA-256 over the RFC 8785 canonical form. The raw receipt object is stored in the snapshot archive at that hash. Redaction is part of the rule: the placeholder string is `"[REDACTED]"` and applies to authorization headers and API keys only; redacting anything the claim depends on invalidates the receipt.

## Failure report artifacts

A `failure_reports[].artifact_hash` is computed exactly like an observation receipt when the failure is a request/response, and exactly like a transcript artifact when it is a model interaction.

## Mismatch semantics

Hashes are receipts, not gates. A validator whose hash differs from the submitter's is not an automatic rejection: pages differ between viewers, and two honest measurements return two different receipts by nature. Each signature records what its signer saw; the validator's signed judgment that the source or the measurement says what the entry says is the attestation. Matching hashes for an unchanged page are the expected case because extraction plus normalization removes nonces, timestamps, and per-visitor markup; matching hashes for observation receipts are not expected and carry no meaning.

## Reference implementation

`normalize.py` in the code repository, with exact dependency versions pinned, is the executable form of this rule. Where the script and this document disagree, this document governs and the script gets fixed.

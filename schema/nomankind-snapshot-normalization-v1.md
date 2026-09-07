# Snapshot Normalization Rule — norm-v1.2

The published, versioned rule the whitepaper (v1.5) and entry schema (v0.6) reference. `snapshot_hash`, `receipt_hash`, and `artifact_hash` are computed by this rule, never over raw bytes. Which version applies is fixed per entry: the entry's `norm_version` names the version in force at its `submitted_at`, and every later hash on that entry (validators, reconfirmers, challengers, failure reporters) uses the same version. norm-v1.2 applies to entries submitted on or after 2026-09-08 and supersedes norm-v1.1 (which applied from 2026-09-03) and norm-v1 (which applied from 2026-09-01); no entries were sealed under either. New versions apply to new entries only, never retroactively.

## Pipeline

1. **Fetch.** One HTTP GET, no JavaScript execution, no cookies, no authentication. Fixed request headers: `User-Agent: nomankind-snapshot/1 (+https://nomankind.ai/norm)`, `Accept: text/html,application/json,application/pdf,text/plain;q=0.9,*/*;q=0.5`, `Accept-Language: en`, `Accept-Encoding: identity`. Follow up to five redirects; the final URL is recorded in the sidecar. Timeout thirty seconds. A page that needs JavaScript to show its content is a source this rule cannot pin; the submitter must cite a static representation instead (the provider's API, a PDF, a plain-text or JSON endpoint, or the archive URI of a receipt). Rendered captures are out of scope for norm-v1.x and will be a later version if needed.

2. **Archive.** Store the raw response body in the content-addressed snapshot archive at `sha256` of the body bytes. Store a sidecar at `<hash>.meta.json` with `{final_url, status, headers, fetched_at, fetcher}` where `fetcher` is the 1F916 identity that fetched. The raw capture is evidence and is never what `snapshot_hash` hashes.

3. **Extract by media type.** The media type is the value of the `Content-Type` response header up to but not including the first `;`, trimmed of surrounding whitespace and ASCII-lowercased. An absent header, an empty value, or `application/octet-stream` means the media type is determined by sniffing (below).

   | Media type | Extraction |
   | --- | --- |
   | `text/html`, `application/xhtml+xml` | The HTML extractor below. |
   | `application/json`, `text/json`, any subtype ending in `+json` | Canonicalize per RFC 8785 (JCS). The canonical UTF-8 bytes are the content; step 4 is skipped. A body that does not parse as JSON is refused with reason `invalid_json`. |
   | `application/pdf` | No extraction under v1.2: `snapshot_hash` is over the raw bytes and equals the archive address. |
   | Any other `text/*` | The decoded text as is. |
   | Anything else (images, binaries) | No extraction; `snapshot_hash` is over the raw bytes, the same value as the archive address. |

   **PDF limitation.** Under v1.2 a PDF is pinned by its bytes, not by its text: two PDFs with identical text but different bytes hash differently, and a re-export of the same document will not match. A pinned TypeScript PDF text extractor is deferred to a later norm version. A submitter who needs the text pinned should cite a text, HTML, or JSON representation instead.

   **Sniffing rule**, applied to the response body exactly as follows. Drop a UTF-8 BOM. Skip leading ASCII whitespace. If the first 1024 bytes decoded as UTF-8 contain `<!doctype html` or `<html`, compared case-insensitively, the type is HTML. Otherwise, if the first byte is `{` or `[` and the whole body parses as JSON, the type is JSON. Otherwise, if the bytes begin with `%PDF-`, the type is PDF. Otherwise, if the whole body decodes as strict UTF-8, the type is plain text. Otherwise the body is raw bytes.

### HTML extraction (norm-v1.2)

The extractor is defined here in full and implemented in this repository; no third-party extractor is part of the rule. The steps run in order.

**E1. Decode.** The body bytes are decoded as UTF-8; a leading BOM is dropped; invalid sequences become U+FFFD. Charset parameters on `Content-Type` are ignored under v1.2 (limitation: a non-UTF-8 page hashes over its replacement-character decoding, so a submitter should cite a UTF-8 representation).

**E2. Tokenize.** Scan left to right. A comment starts at `<!--` and ends at the first following `-->`, or at the end of the document if unterminated; comments are dropped. A markup declaration or processing instruction starts at `<!` (not `<!--`) or `<?` and ends at the next `>`; it is dropped. A tag starts at `<` followed by an ASCII letter, or by `/` and an ASCII letter, and ends at the first `>` that is not inside a quoted attribute value (single or double quotes); an unterminated tag runs to the end of the document and is dropped. Any other `<` is text. The tag name is the run of characters after `<` or `</` up to the first whitespace, `/`, or `>`, ASCII-lowercased. A start tag whose last non-whitespace character before `>` is `/` is self-closing.

**E3. Remove elements with their content.** For a start tag named `head`, `script`, `style`, `template`, `noscript`, `nav`, `header`, `footer`, `aside`, or `svg`: drop everything from the start tag through the matching end tag of the same name, and if there is none, through the end of the document. For `script` and `style` the element ends at the first end tag of the same name (nested start tags inside are text, as in browsers). For the other names, count nesting: each nested start tag of the same name needs its own end tag. A self-closing start tag of these names drops only itself. Removal runs over the whole document before scoping.

**E4. Scope.** After removal, if any `main` start tag remains, the scope is the content of every outermost `main` element in document order, joined by a single newline; otherwise, if any `article` start tag remains, the content of every outermost `article` element the same way; otherwise the content of the `body` element; otherwise the whole remaining document. The content of an element is everything between its start tag and its matching end tag, counting nesting of the same name; with no matching end tag, through the end of the document. Outermost means an element nested inside a collected one is not collected again. A self-closing `main` or `article` start tag is an element with empty content, and still counts as present for choosing the scope.

**E5. Tags to text, within the scope.** A `br` tag (start or self-closing) becomes a newline. A start or end tag of `td` or `th` becomes a single space. A start or end tag of any element in the block list becomes a newline. Every other tag (start, end, or self-closing, including unknown names) becomes nothing. Block list, exactly: `address`, `article`, `blockquote`, `caption`, `dd`, `details`, `dialog`, `div`, `dl`, `dt`, `fieldset`, `figcaption`, `figure`, `form`, `h1`, `h2`, `h3`, `h4`, `h5`, `h6`, `hgroup`, `hr`, `legend`, `li`, `main`, `ol`, `p`, `pre`, `section`, `summary`, `table`, `tbody`, `tfoot`, `thead`, `tr`, `ul`.

**E6. Character references**, on the resulting text, in a single pass; decoded output is never decoded again, so `&amp;lt;` yields `&lt;`. `&amp;`, `&lt;`, `&gt;`, `&quot;`, and `&apos;` become the character they name. `&nbsp;` becomes a space (U+0020). Numeric references `&#NNN;` (decimal) and `&#xHHHH;` or `&#XHHHH;` (hex) become the code point, except that U+00A0 becomes a space and code point 0, surrogates D800–DFFF, or anything above 10FFFF become U+FFFD. Any other `&` sequence, including unknown named references and references without the closing `;`, stays literal. Finally every literal U+00A0 in the text becomes a space.

**E7.** The result goes through steps 4 and 5.

4. **Normalize text.** In order: apply Unicode NFC; convert CRLF and lone CR to LF; remove U+200B, U+200C, U+200D, and U+FEFF everywhere; collapse every run of spaces and tabs to a single space; strip leading and trailing spaces and tabs on each line; collapse three or more consecutive newlines to two; strip leading and trailing whitespace from the whole document. (Change from v1.1: leading spaces and tabs on each line are now stripped too, so source indentation cannot change a hash.)

5. **Hash.** Encode the result as UTF-8 and compute SHA-256. Format: `sha256:<64 lowercase hex>`.

## Transcript artifacts (behavior and misbehavior entries)

The artifact is a JSON object carrying exactly these six keys and no others: `model`, `prompt`, `parameters`, `output`, `predicate`, `observed_at`. A missing key or an extra key is not hashed; the artifact is refused with reason `transcript_shape`. These are the entry's `evidence` fields minus `provider_statement`, which is a citation and not part of the measurement. Its hash is `sha256:` followed by the SHA-256 of the UTF-8 bytes of the RFC 8785 canonical form of that object. A validator's reproduction transcript and a reconfirmer's re-run transcript use the same key set with the runner's own `output` and `observed_at`; `model`, `prompt`, `parameters`, and `predicate` are copied from the entry unchanged.

## Observation receipt artifacts (observed entries outside behavior and misbehavior)

An observed entry carries `observation.receipt_hash`; each approving validator and each reconfirmer carries its own receipt hash. The receipt is a JSON object carrying exactly these eight keys and no others: `method`, `subject`, `test` (copied from the entry's `observation.test`), `request` (the exact request made, after redaction), `response` (status, the headers the test names, body), `billing` (for `metered_call`: the provider's billing line as returned or exported, after redaction; `null` otherwise), `observed_at`, and `observer` (1F916 identity). A missing key or an extra key is refused with reason `receipt_shape`. `method` must be one of the values of the entry schema's `observation.method` enum; a method outside it is refused with reason `unknown_method`. `billing` must be `null` for every method except `metered_call`, where it must be present; either way round, a `billing` line that does not match the method is refused with reason `billing_shape`. Its hash is `sha256:` followed by the SHA-256 of the UTF-8 bytes of the RFC 8785 canonical form. The raw receipt object is stored in the snapshot archive at that hash. Storing it there is the application's step at submit and validation time, outside this pure rule, which only decides the hash.

Redaction is part of the rule. The placeholder string is `"[REDACTED]"`; a value is redacted when it is a string containing that placeholder. Redaction is permitted only at these places, and nowhere else:

- any value under `request.headers`, at any depth;
- any value under `request`, at any depth, whose own key, or any ancestor key below `request`, is a credential key or an identifier key;
- any value under `billing` whose own key, or any ancestor key below `billing`, is an identifier key.

Credential keys, exactly: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `api_key`, `api-key`, `apikey`, `x-api-key`, `key`, `token`, `access_token`, `refresh_token`, `secret`, `password`, `bearer`. Identifier keys, exactly: `account`, `account_id`, `organization`, `organization_id`, `org`, `org_id`, `project`, `project_id`, `billing_account`, `billing_account_id`, `customer`, `customer_id`, `user`, `user_id`, `workspace`, `workspace_id`, `tenant`, `tenant_id`. Keys are compared ASCII-lowercased with `-` and `_` treated as the same character, so `X-Api-Key` and `Api_Key` both match.

`"[REDACTED]"` anywhere else invalidates the receipt with reason `redacted_load_bearing`: anywhere under `response`, `subject`, `test`, `method`, `observed_at`, `observer`, at a non-identifier value under `billing`, or at any other value under `request`. This is the mechanical form of the older rule that a redaction may not replace anything the `test` predicate reads (status codes, error codes, prices, limits, model identifiers, counts). The refusal names the JSON pointer of the first offending value in a deterministic walk: object keys in sorted order, arrays by index, strings inside arrays included.

## Failure report artifacts

A `failure_reports[].artifact_hash` is decided by key set. An object carrying exactly the transcript keys is hashed by the transcript rules; an object carrying exactly the receipt keys is hashed by the receipt rules; anything else is not a valid failure report artifact and is refused with reason `unknown_artifact`.

## Mismatch semantics

Hashes are receipts, not gates. A validator whose hash differs from the submitter's is not an automatic rejection: pages differ between viewers, and two honest measurements return two different receipts by nature. Each signature records what its signer saw; the validator's signed judgment that the source or the measurement says what the entry says is the attestation. Matching hashes for an unchanged page are the expected case because a fixed fetch plus extraction plus normalization removes nonces, timestamps, and per-visitor markup; matching hashes for observation receipts are not expected and carry no meaning.

## Reference implementation

`src/extract.ts`, `src/normalize.ts`, and `src/artifact.ts` in this repository are the executable form of this rule and ship with it: the specification and the code are one artifact (D-012). Where the code and this document disagree, this document governs and the code gets fixed.

## Changes from norm-v1.1

- A pure-TypeScript extractor, defined in this document, replaces the pinned trafilatura and `pdftotext` dependencies.
- PDFs are hashed over their raw bytes; text extraction is deferred to a later version.
- The sniffing rule is written out explicitly instead of being left to the implementation.
- A body served as JSON that does not parse as JSON is refused with reason `invalid_json`.
- Step 4 now strips leading spaces and tabs on each line as well as trailing ones.
- U+00A0 becomes a space, both from `&nbsp;` and literally.
- The redaction rule is mechanical: permitted locations, two exact key sets, a key-matching rule, and a deterministic first-offender pointer.
- A failure report artifact's kind is decided by its key set.

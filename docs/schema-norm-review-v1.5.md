# Review: entry schema v0.5 and norm-v1 against whitepaper v1.5 and the PoC milestones

Date 2026-09-03. Scope: `nomankind-entry-schema.json` (v0.5), `nomankind-snapshot-normalization-v1.md`, the example entry, and Part B of the PoC plan. Verdict: the schema and norm rule are structurally sound and track v1.5 closely. The gaps below are real but small, and most are one-line edits. Blockers for the PoC are marked (B). Everything else is a v0.6 / norm-v1.1 item.

## A. Schema vs whitepaper

**A1 (B). Test acceptance is missing.** Section 4 says validators first judge the proposed test, and a rejected test drops the entry to stated. The schema has no way to state the proposed test (only `observation.method` and free `notes`) and no `test_accepted` on approver records. M10 needs both. Fix: add `observation.test` (the predicate and procedure, plain text, part of the signed core) and `approvers[].test_accepted` (boolean, required when the entry is observed).

**A2 (B). Behavior artifacts lack sampling parameters and the predicate.** Section 4 freezes model, prompt, output, sampling parameters, observation date, and a checkable predicate over outputs. `evidence` has no `parameters` and no `predicate`, so a validator has nothing to count `holds` against. Fix: add `evidence.parameters` (object, frozen) and `evidence.predicate` (string, frozen). The norm-v1 transcript artifact must then include both.

**A3. Reconfirmation cannot carry a reproduction.** Section 4 says reconfirming a behavior entry means rerunning under n-of-k; Section 7 says observed entries reconfirm by fresh measurement. `reconfirmations[]` has only `snapshot_hash`. M11 requires a passing reproduction. Fix: add optional `reproduction` and `observation` objects to the reconfirmation record, same shapes as on approvers.

**A4. Version-in-force conflict.** Entry `snapshot_hash` says the norm version in force at `submitted_at` applies; approver `snapshot_hash` says the version in force at `signed_at`. Across a norm cutover those differ and honest hashes stop matching. Fix: every hash on an entry uses the version in force at the entry's `submitted_at`. Say so once in `$comment` and drop the `signed_at` wording.

**A5. Small-pool wording.** `approvers` description says exactly three approvals with exactly one random draw; `verified_at` says "when the third approval landed". Section 6 verifies on two approvals with no draw under ten trusted operators. Fix: "the promoting approval" and note the pool switch.

**A6. Timed-out assignments cannot be represented.** The `approvers` comment says timed-out assignments stay in the array, but `decision` allows only approve or reject. Fix: either add `"missed"` to the enum or state that misses live in the event log, not the array. The event log is cleaner.

**A7. `evidence_tier` says "optional" but is required.** The description says optional outside behavior; it is in `required` and in the signed core. Fix wording: required, defaults to stated in the submit tool.

**A8. No norm version on the entry.** Offline recompute (M12) needs to know which rule produced each hash. It is derivable from `submitted_at` plus the policy table, but a `norm_version` field in the core makes the verify script self-contained. Optional.

**A9. Provider-statement path and the observed tier.** Section 4 says behavior entries are observed by rule, yet an entry can verify on a provider statement with zero reproductions. That entry carries `observed` while resting on a document. Whitepaper-level tension, not a schema bug. Options: require at least one reproduction even with a statement, or let that path derive tier stated. Decide before M10.

**A10. `citation` and `evidence.provider_statement` overlap.** For behavior entries the whitepaper says the citation IS the provider statement when that is the basis. The schema stores it twice. Harmless; say they must be equal, or make `provider_statement` a boolean `basis` flag.

**A11. Events the entry cannot hold.** Assignment, assignment_missed, pool_snapshot, revalidation requests, read counts, and stakes are whitepaper mechanisms with no home in the entry schema. Correct: they belong in the event log (M4). Worth a short companion `events.json` schema before M9 so the verify script has something to check against.

**A12. Frame scope.** Section 12 names the frame gap as a future schema version. v0.5 matches v1.5 by omitting it. Fine.

Category enum, five states, derived fields, supersedes-in-core, bare-key authors, failure reports, seal shape, confidence null: all match v1.5. The example entry matches the worked entry in Section 3 field for field.

## B. norm-v1 vs whitepaper

**B1 (B). Fetch is unspecified.** The rule says "fetch the source" and hands HTML to trafilatura. Provider doc pages (the example citation included) are often JS-rendered; a raw GET returns a shell and hashes to nothing useful. The whitepaper's promise that two honest captures match depends on a pinned fetch. Fix: pin the fetch as part of the rule: raw HTTP GET or a pinned headless render (pick one), fixed User-Agent string, fixed Accept and Accept-Language, no cookies, redirects followed to a limit, and the final URL recorded in the archive sidecar.

**B2. Transcript artifact field list is loose.** "The entry's evidence fields" is ambiguous about `provider_statement` and will be wrong once A2 adds parameters and predicate. Fix: enumerate the exact keys hashed.

**B3. Redaction is too narrow for a public archive.** Billing lines "verbatim" can carry account and organization identifiers. The archive is mirrorable. Fix: permit redaction of account identifiers that the claim does not depend on, same placeholder, and keep the rule that redacting anything load-bearing invalidates the receipt.

**B4. Header storage.** Raw archive address is sha256 of body bytes, but headers are "stored" without saying where. Fix: one sentence naming a sidecar `<hash>.headers.json`.

**B5. Mismatch semantics** match Section 4 exactly. Good.

## C. Milestones vs schema and norm

**C1 (B). M2 core field list is wrong.** It lists claim, citation, snapshot_hash, before, after, effective, evidence, supersedes, submitter, submitted_at. The schema core also has id, subject, category, evidence_tier, observation, author_operator, and uses `effective_at` and `author`. Milestone text wins over the paper by rule, so builders will freeze the wrong bytes. Fix: point M2 at the schema `$comment` list verbatim.

**C2 (B). M5 contradicts norm-v1.** M5 hashes transcript artifacts "as raw text"; norm-v1 hashes the JCS-canonical JSON object. Fix M5 to say JCS.

**C3 (B). M5 stack mismatch.** norm-v1 pins trafilatura and pdftotext (Python, poppler); the PoC is TypeScript with no new dependencies. Decide: either the PoC ships a minimal TS extractor and logs the deviation in `docs/GAPS.md`, or `normalize.py` is allowed as the one non-TS component. The second keeps hashes portable to production.

**C4 (B). M10 puts `evidence.test` on non-behavior entries.** The schema's `allOf` forces `evidence` null outside behavior, so that fixture fails M1 validation. Fix: use `observation.test` per A1.

**C5. M11 reconfirmation** needs A3 landed first, or the reproduction check has no field to read.

**C6. M1 test "example passes"** will keep passing after v0.6 only if the example is updated with `observation.test` and `approvers[].test_accepted`. Update both files together.

## Suggested order

Ship schema v0.6 (A1 to A7) and norm-v1.1 (B1 to B4) as one commit before M1, since M1 copies the schema and M5 copies the norm doc. Patch M2, M5, M10 text in PLAN.md in the same commit. Decide A9 and C3 up front; both are one-line decisions that block later milestones.

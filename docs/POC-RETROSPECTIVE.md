# Proof-of-concept retrospective

The proof of concept (September 2026, fourteen milestones plus a storage port) was retired on 2026-09-06 and does not live in this repository. This document is what it taught.

## 1. Summary

The PoC set out to prove the whitepaper's core mechanics: an append-only, signed, hash-chained
log where every status is derived from events (never set directly); operator-validated consensus
that switches rule as the trusted pool grows past 10; two evidence tiers (stated vs observed, with
a checkable predicate and n-of-k acceptance); Merkle-sealed batches with mock witnesses and an
anchor stub; an offline two-file-and-a-script verifier; a read API issuing signed receipts.

Shipped: M1 to M14 plus DEPLOY-1, 178 vitest tests green, a demo script running the paper's
demo checkpoint end to end (seed, three outside operators validate, entry reaches verified,
offline verify exits 0), and a D1 + R2 storage port behind the same function names, core kept
synchronous.

## 2. What held

- **Events as the only source of truth** — `status`, `stale`, `superseded_by`, `entry.seal` are
  always recomputed from events, never written directly; unchanged from M4 through the storage port.
- **Frozen 17-key core + JCS hashing** — the core extraction, canonicalization, and entry hash from M2
  were never revised; every later milestone hashed against the same core.
- **One policy module as the sole home for numbers** — pool switch, n/k, staleness windows, seal
  interval, slot count all landed there, including the M11 fold-in.
- **Injected clock** — only the CLI and the HTTP adapter read wall time, keeping every derive/
  consensus/staleness test deterministic and table-driven.
- **A storage seam (DEPLOY-1)** — a synchronous record-level interface let D1 + R2 arrive
  without touching derive, consensus, seal, or verify, exactly as designed.
- **Signatures in the event payload** — the schema has no signature field for approver/
  reconfirmation records, so `approver_sig`/`reconfirmation_sig` travel in the event payload, decided
  once at M7 and never revisited.

## 3. What the GAPS taught

The PoC kept a one-line log of every deviation from the paper or the milestone text (13 entries). Each, and its lesson for the rebuild:

- **M1** (hand-authored example entry): a spec with no worked example costs a detour; ship a
  canonical example with the schema itself.
- **M2** (seed fee rate/cap are 0 placeholders): don't let missing policy numbers block a
  milestone; stub visibly and track as an open question.
- **M5** (reduced HTML extractor, not trafilatura): a stand-in for a pinned external tool must be
  named as a stand-in, not left to look like the real thing.
- **M8** (trusted count over the whole log): a pool-size threshold must be evaluated at the
  decisive event's position from the first version, not patched in later.
- **M8** (precondition reduced from the paper's two conditions to one): when milestone text
  simplifies a paper rule, record which condition was dropped.
- **M9** ("at least one" random approver, not "exactly one"): a replacement-draw path can make a
  literal reading unsatisfiable; re-check predicates against every path, not just the happy one.
- **M10** (checkable-predicate is a trimmed non-empty-string check): judgment-shaped requirements
  cannot be faithfully stubbed by a syntactic check; the rebuild needs a real judgment step.
- **M11** (read-share slot count was a literal): any bare number in a derive/state module is a
  policy leak; enforce policy-only-in-the-policy-module by review, not memory.
- **DEPLOY-1** (whole D1+R2 working set loaded per request): fine at PoC volume; the rebuild's
  storage must be query-shaped from the start, not a literal port of a file layout.
- **DEPLOY-1** (write path still took a keyfile string, not a key reference): finish both sides of a
  read/write seam in one milestone, or name the gap explicitly.
- **DEPLOY-1** (no test for a stale materialized entry surviving rebuild-through-backend): a
  refactor claiming "no behavior change" still needs its own regression test.
- **DEPLOY-1** (DNS fixture load failure silently became an empty record set): a stub's failure
  should fail loud, not silently degrade into what looks like a policy decision.
- **DEPLOY-1** (a hand-generated TypeScript copy of the JSON schema): a file that must
  mirror another needs an equality test from the moment it's created. Better: never copy the schema.

## 4. Bugs found the hard way

- **M8 trusted-count over the whole log.** Symptom: entries could verify retroactively or flip
  back to draft as the pool crossed 10. Fix: M9's position-aware trusted count. Rule: evaluate
  growing-set thresholds at the decision's position, never the set's current size.
- **M4 write-before-validate.** Symptom: risk of persisting an entry before full schema
  validation. Fix: submit validates the complete assembled entry before append/materialize.
  Rule: validate the whole object before any write, never validate-then-patch-then-write.
- **M10 loosened test-acceptance rule.** Symptom: one builder relaxed the `test_accepted` majority
  rule to make fixtures pass, so an entry with failing tests could still count as accepted. Fix:
  a second builder restored the strict rule and corrected the fixtures instead. Rule: when a test fails,
  suspect the fixture before the rule; never weaken a spec rule to make data pass.
- **M11 literal slot count.** Symptom: the read-share slot count was hardcoded in the state module.
  Fix: M12 moved it to the policy module. Rule: no bare policy number outside the policy module,
  checked every milestone at review.
- **M13 unvalidated status filter.** Symptom: the entries list endpoint's status filter accepted any string.
  Fix: filter constrained to the schema's known status values. Rule: every enum-shaped query
  parameter is validated against that enum before it reaches filter logic.
- **M14 fixture seal key.** Symptom: the verified-entry fixture had no `seal` key at all, so the
  verifier grew a special case for "seal absent" that hid a real derivation difference. Fix: the
  fixture carries an explicit `seal: null` and the special case was removed. Rule: fixtures carry
  every derived field explicitly, even when null; the verifier never special-cases absence.

## 5. Modules the spec requires

A map of what the PoC's code had to contain, by role, so the rebuild plans the same surface from the spec rather than copying code. Names are the PoC's; the rebuild chooses its own.

SPEC-DRIVEN (pure rules from the paper and schema; the rebuild's kernel package): schema validation
(Ajv 2020, strict, formats on), the 17-key frozen core, hashing (JCS, tagged SHA-256, entry hash),
policy (every number), crypto (Ed25519), identity (agent ids), derive (entry and status from events),
evidence (n-of-k, test acceptance, transcript rules), merkle (tree, proof, inclusion verification),
verify (offline recompute-and-diff).

MIXED in the PoC (a spec rule entangled with storage; the rebuild keeps these pure from the start):

- state — sidecar fields (`effective_tier`, `needs_replacement`, slot rotation) are rules;
  persistence is not. Keep a pure compute-state-fields function.
- submit — id, `submitted_at`, and tier fill-in plus the supersedes check are rules; the append-
  and-materialize call is not. Keep a pure build-submitted-core function.
- validate — exclusion, `test_accepted`, `assigned_random` rules are rules; the signed-event
  append is not. Keep a pure check-validation function.
- supersede — the subject/category match rule is near-pure already; export it standalone for the verifier.
- reconfirm — eligibility and reproduction/observation adequacy are rules; the append and
  slot-rotation write are not. Keep a pure can-reconfirm function.
- seal — Merkle batching and the witness rule are rules; seal/anchor writes are not. Keep a pure build-seal function.
- receipts — hashing/signing is a rule; the counter's persistence is not. Keep a pure build-receipt function.
- assign — the deterministic draw is near-pure already; event writes and the mock beacon are not.
- operators — attestation, provider, and exclusion checks are rules; the DNS stub and registry
  persistence are not. Keep a pure check-registration function.
- snapshot — text normalization and the snapshot, transcript, and receipt hashes are rules;
  HTML extraction and the archive read/write are fetch stubs.

INFRASTRUCTURE (PoC-only shapes, rebuilt for Workers and D1 from scratch): event log I/O and rebuild,
filesystem and in-memory backends, D1/R2 load-all/flush-all, the Workers entry, the fetch handler,
the `node:http` adapter, the CLI, the data-dir-to-SQL exporter.

## 6. Lessons for the rebuild

- **Web app.** Authenticated write endpoints replace the CLI as the only ingest path; D1-native,
  query-shaped storage replaces load-all/flush-all; real DNS check, source fetch, witness set, and
  beacon replace the stubs; a browsing UI is needed from the start, not after.
- **Infrastructure.** Stay on Cloudflare Workers (free tier, proven by DEPLOY-1); two environments
  per Worker (`demo` staging with throwaway keys, `production` with a real maintainer-key secret);
  GitHub Actions deploys, never manual runs.
- **Process.** One milestone per pull request, green before merge; keep the builder/builder/
  reviewer pattern (reviewers caught a real defect in most milestones); policy numbers only in
  the policy module; derived fields never set directly, enforced by review.

## 7. Deferred by the PoC, to be planned in the rebuild

- **Delta stream** — sealed-position events with inclusion proofs, supersession flattening, unlearn
  signals, sync receipts; each delivered verified entry counts as a read.
- **Disputes** — staked correction disputes, exclusion of original signers, revalidation requests
  with caps, upgrade of a request with citation to a dispute.
- **Standing and ledger** — standing by the published formula, the 15/5/5/5 read-share split with
  holdback and clawback, the seed fee under a cap, stale half-rate and bounty on reconfirm.
- **Failure reports and drift** — threshold-triggered revalidation counting distinct verified
  operators, probe-set drift attestation, confidence kept null with its raw inputs exposed.
- **Authenticated write path** — the PoC's Worker could only read and issue receipts.
- **Real operators** — real DNS check and source fetching, a real witness set, a real beacon.
- **Production key** — the maintainer key as a Worker secret on `app.nomankind.ai`.

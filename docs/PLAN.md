# nomankind PoC: orchestrator prompt + milestones (whitepaper v1.5)

Built from WHITEPAPER.md v1.5 (Sept 2026). Replaces the old milestone plan. This file lives at `docs/PLAN.md`; the whitepaper at `paper/WHITEPAPER.md`; schema, example, and norm rule under `schema/`. Paste Part A into Claude Code each session. Change only the `MILESTONE:` line.

Schema is v0.6 and the normalization rule is norm-v1.1 (both updated 2026-09-03 after the coherence review in `schema-norm-review-v1.5.md`). Two decisions fixed there and binding on every milestone: a behavior or misbehavior entry verified on a provider statement with no passing reproduction has effective tier stated (sidecar, core untouched); and the PoC ships a reduced TypeScript HTML extractor, logged in `docs/GAPS.md`, with `normalize.py` as the production reference.

---

# Part A: orchestrator prompt (paste this)

## Role and budget

You are the orchestrator (Fable 5.1). You do not write product code. You plan, delegate, review, commit. Tokens are the top constraint. Rules, no exceptions:

1. One milestone per session, the one in `MILESTONE:` below. Never start the next. Never refactor earlier work unless the current milestone cannot pass otherwise.
2. All coding, testing, and file reading goes to the Agent tool with `model: sonnet`. Max 4 agents per session, max 2 running at once. Each agent gets one narrow job and a named file list.
3. Every agent is medium effort. Every agent prompt includes: "Medium effort. Read only the files listed. No exploration. No extra features. No new dependencies. Return a summary under 150 words, never file contents."
4. Never read whole source files into your own context. Use agent summaries and `git diff --stat`. Read lines yourself only to settle a review disagreement.
5. No web searches, no docs lookups, no dependency changes.
6. If a milestone needs more than 4 agent runs, stop, split it in two in `docs/PLAN.md`, report the split, finish only the first half.
7. Session ends when `npm test` is green and one commit exists. Print 5 lines: milestone, files touched, test count, agents used, deferred items.

## Fixed assumptions (paste into every agent prompt)

TypeScript, Node 20+, no framework. `vitest` tests. `ajv` + `ajv-formats` for schema (Ajv 2020 build, strict mode). `canonicalize` for RFC 8785 JCS. Node `crypto` for Ed25519 and SHA-256. Storage is local JSON and JSONL files under `data/`. Schema is `schema/entry.json` (copy of `nomankind-entry-schema.json` v0.6). Layout: `schema/`, `src/`, `src/cli.ts` (`nmk` command), `data/` (gitignored except fixtures), `test/`, `fixtures/`, `docs/`. Policy numbers live in `src/policy.ts` and nowhere else. Status and every derived field are recomputed from events, never set directly. A fake clock is injected everywhere time matters. Field names come from the schema exactly; never invent aliases.

## Source of truth

`paper/WHITEPAPER.md` is the spec, `schema/entry.json` is the shape, `schema/nomankind-snapshot-normalization-v1.md` is the hash rule, `docs/PLAN.md` Part B is the build order. Milestone text wins over the paper for the PoC, and the schema wins over milestone text for field names and shapes; log any gap as one line in `docs/GAPS.md`. Agents implement only what the milestone says.

## Session workflow

1. Plan (you, no agents). Read only the current milestone section of `docs/PLAN.md`. Write a 5 to 10 line task split to `docs/sessions/M<n>.md`. Slots A, B, C build. Slot D reviews.
2. Build. Each builder gets: assumptions line, milestone text verbatim, its file list, the Test line. Builders write code and tests, run `npm test`, iterate to green inside their scope. A and B run in parallel only if file lists do not overlap.
3. Review (D). Reads `git diff`, checks the Test line and the whitepaper section named in the milestone, runs `npm test`, returns pass or a numbered defect list under 10 lines. One fix pass max, sent to one builder. Leftovers go to `docs/GAPS.md`.
4. Commit (you). `git add -A && git commit -m "M<n>: <one line>"`. Mark the milestone `[done]` in `docs/PLAN.md`. Print the status report. Stop.

## Agent prompt template

```
Medium effort. Milestone <n> of the nomankind PoC.
Assumptions: <fixed assumptions line>.
Whitepaper section to honor: <section name>.
Your files, only these: <list>.
Milestone text: <verbatim>.
Tests you must make pass: <Test line>.
Rules: read only your files plus test helpers. No new dependencies, no extra features, no edits outside your files. Run `npm test` until green. Return under 150 words: built, test count, blockers. No file contents.
```

MILESTONE: 1

---

# Part B: milestones (v1.5, schema v0.6)

Each is one session. Each ends green and committed. Stop at M12 for the demo the paper names: three operators outside the maintainer's promoting a seeded entry to verified. M13 to M18 are optional.

## M1. Scaffold + schema validation
Builds: repo skeleton, `validateEntry(obj)` with Ajv draft 2020-12, formats on, strict. Copy the example entry to `fixtures/entry-example.json`.
Files: `package.json`, `tsconfig.json`, `vitest.config.ts`, `schema/entry.json`, `src/schema.ts`, `fixtures/entry-example.json`, `test/schema.test.ts`.
Test: example passes; missing `evidence_tier` fails; `category=behavior` without evidence fails; `evidence_tier=observed` without an observation fails; observed entry with an approver whose `test_accepted` is null fails; stated entry with `test_accepted` null passes.
Section: The log. Depends: none.

## M2. Frozen core, JCS, hashing, policy table
Builds: `extractCore(entry)` returns exactly the schema `$comment` core key set: `id, subject, category, claim, before, after, effective_at, evidence_tier, evidence, observation, citation, snapshot_hash, norm_version, supersedes, author, author_operator, submitted_at` (nulls present, never absent; nothing else). `canonicalCore`, `sha256Tag` (`sha256:<hex>`), `entryHash`. `src/policy.ts` holds every number from the paper: pool switch 10, assignment window 72h, n=10 k=8, staleness 90 pricing/limit and 30 behavior, holdback 30d, split 15/5/5/5, seal interval 5m, failure report threshold 3, seed fee rate and cap, current norm version `norm-v1.1`.
Files: `src/core.ts`, `src/hash.ts`, `src/policy.ts`, `test/core.test.ts`.
Test: key order does not change bytes; derived field injected is stripped; two entries differing only in `status` hash equal; core key set equals the 17 listed names exactly; policy exports every listed constant.
Section: The log. Depends: M1.

## M3. Ed25519 keys, sign, verify, agent ids
Builds: `generateKeypair`, `signCore`, `verifyEntrySignature`. Agent id `1F916:<base64url pubkey>` (provisional). CLI `nmk keygen`, `nmk sign`.
Files: `src/crypto.ts`, `src/identity.ts`, `src/cli.ts`, `test/crypto.test.ts`.
Test: sign then verify true; one byte of `claim` flipped verifies false; change to a derived field still verifies; keygen writes both keys.
Section: Identity and operators. Depends: M2.

## M4. Event log + submit
Builds: append-only `data/events.jsonl` (`{position, prev_hash, type, entry_id, at, payload, sig}`), materialized `data/entries/<id>.json`, `rebuild()`. `submit(core, keyfile)` fills id, `submitted_at`, `norm_version` from policy, `evidence_tier` default `stated` when absent (forced `observed` for behavior/misbehavior), signs, appends `submitted`, derives `status=draft`, staleness fields, and writes only if the full entry validates. Every event is hash-chained from this milestone so sealing later is a wrapper. CLI `nmk submit`, `nmk get`, `nmk list`.
Files: `src/store.ts`, `src/derive.ts`, `src/submit.ts`, `src/cli.ts`, `test/store.test.ts`.
Test: submit writes one event and one entry; entry validates; tampered signature rejected; delete entries dir, `rebuild()` reproduces identical files; editing an earlier event line breaks the chain check; submitted entry carries `norm_version` from policy.
Section: Lifecycle, Submit and Seal. Depends: M1 to M3.

## M5. Snapshot normalization + snapshot archive
Builds: `normalizeText` implementing norm-v1.1 steps 4 and 5 exactly; `extractHtml` as a reduced stand-in for step 3 (strip script, style, nav, header, footer, comments; text of the rest; log the deviation from trafilatura in `docs/GAPS.md`). `snapshotHash(bytes, contentType)`; JSON goes through JCS and skips step 4. `submit --source <file>` computes the hash itself and stores raw bytes at `data/snapshots/<sha256-of-bytes>` plus `<hash>.meta.json` sidecar. `transcriptHash(evidence)` hashes the JCS-canonical object of exactly `{model, prompt, parameters, output, predicate, observed_at}`; `receiptHash(receipt)` hashes the JCS-canonical receipt object. No fetching in the PoC; sources are files.
Files: `src/snapshot.ts`, `src/submit.ts`, `fixtures/pages/*.html`, `test/snapshot.test.ts`.
Test: two pages differing only by nonce and timestamp hash equal; changed price text hashes differently; raw file and sidecar land in the archive; transcript artifact hash is key-order independent and changes when `parameters` changes; a JSON source hashes equal across whitespace and key order.
Section: Evidence, Snapshots. Depends: M4.

## M6. Operator registry
Builds: `data/operators.json` entries `{id, agents[], trusted, is_provider, attestation_sig, dns_domain}`. `registerOperator(keyfile, domain, attestation)` refuses `is_provider=true`, requires a signed independence attestation, appends `operator_registered`. Maintainer operator flagged `is_maintainer`. `setTrusted(id)` appends `trusted_named` (genesis bootstrap, logged as such). DNS check is a stub returning fixture data.
Files: `src/operators.ts`, `src/cli.ts`, `fixtures/operators/*.json`, `test/operators.test.ts`.
Test: provider refused; missing attestation refused; genesis naming writes a public event; agent to operator lookup works; maintainer cannot be trusted.
Section: Identity and operators; Deployment (joining steps). Depends: M4.

## M7. Validation signatures + exclusions
Builds: `validate(entryId, keyfile, decision, {reason, snapshot_hash, test_accepted?, observation?, reproduction?})` appends a signed `approval` or `rejection` event and an approver record with its own signature. Enforce: agent belongs to a registered operator; not the submitter's operator; not the maintainer's; not a provider; approve needs `snapshot_hash`; reject needs `reason`; observed entry needs boolean `test_accepted`; one signature per operator per entry. No status change yet.
Files: `src/validate.ts`, `src/cli.ts`, `test/validate.test.ts`.
Test: three operators approve, three records, still draft; submitter's operator refused; maintainer's agent refused; approve without hash refused; observed approve without `test_accepted` refused; second signature from same operator refused.
Section: Lifecycle, Validate. Depends: M3, M6.

## M8. Consensus with pool-size switch
Builds: `deriveStatus(events, trustedCount)`. Pool under 10: 2 approvals verify, 2 rejections reject, no replacement. Pool 10 or more: 3 approvals with exactly one `assigned_random=true` verify; 2 rejections reject; 2 approve + 1 reject sets `needs_replacement` in sidecar `data/state/<id>.json`. Verification precondition: at least one trusted operator exists, else stay draft. `verified_at` is the promoting approval's `signed_at`.
Files: `src/derive.ts`, `src/state.ts`, `test/consensus.test.ts`.
Test: table-driven with trustedCount 3 and 10: [A,A] small pool verified; [A,A] large pool draft; [A,A,A] large pool with one random verified; zero random draft; [R,R] rejected; [A,R,A] large pool needs_replacement; zero trusted stays draft.
Section: Lifecycle, Validate. Depends: M7.

## M9. Random assignment, pool snapshot, mock beacon
Builds: `commitPoolSnapshot()` appends `pool_snapshot` event before a beacon round. `drawValidator(entryId, poolSnapshot, beacon)` = sha256(entryId || sorted pool || beacon) mod length, excluding submitter's operator and prior signers. Mock beacon `data/beacon.json` `{round, value}`. `assign(entryId)` writes `assigned` with a 72h deadline. `expireAssignments(now)` writes `assignment_missed` and redraws next round (event log only; nothing lands in `approvers`). `validate` sets `assigned_random=true` only when signer matches the open assignment. Replacement draw for M8 `needs_replacement`.
Files: `src/assign.ts`, `src/validate.ts`, `src/derive.ts`, `test/assign.test.ts`.
Test: same inputs same draw; beacon change changes draw; pool snapshot must precede the round used; submitter never drawn; non-assigned claiming random refused; missed deadline redraws and adds no approver record; replacement draw resolves [A,R,A] to verified or rejected.
Section: Lifecycle, Validate; Identity (c/N). Depends: M8.

## M10. Evidence tiers, test acceptance, n-of-k
Builds: observed submissions outside behavior/misbehavior carry `observation.test` and `observation.receipt_hash` (schema shape, nothing added to `evidence`). Each validator's decision carries `test_accepted`. If the majority of decisions reject the test, write `effective_tier=stated` to the state sidecar (core untouched) and validate as a document. If accepted, an approval must carry `observation {method, receipt_hash, observed_at, runs, holds}`; predicate holds when `holds >= k` for `runs = n`; majority of approvals decides, else stay draft. Behavior and misbehavior: observed by rule; approvals carry `reproduction {model, output, observed_at, runs, holds}` counted against `evidence.predicate`; verified requires either `evidence.provider_statement` (which must equal `citation`) or at least one approval with a passing reproduction; provider-statement basis with no passing reproduction writes `effective_tier=stated` to the sidecar. A validator rejects at draft with reason code `no_predicate` when `evidence.predicate` or `observation.test` does not state a checkable predicate.
Files: `src/evidence.ts`, `src/validate.ts`, `src/derive.ts`, `src/state.ts`, `test/evidence.test.ts`.
Test: observed pricing with test rejected by 2 of 3 verifies with sidecar `effective_tier=stated`; accepted test with 8/10 verifies observed; 7/10 stays draft; behavior with no statement and no reproduction stays draft; behavior with provider_statement and 2 approvals (small pool) verifies with sidecar `effective_tier=stated`; behavior with one 8/10 reproduction verifies observed; provider_statement not equal to citation refused at submit.
Section: Evidence, Two tiers; Behavior and misbehavior. Depends: M8.

## M11. Supersession, staleness, reconfirmation
Builds: `supersedes` checked at submit: target exists, same subject and category, same attribute string. When the new entry verifies, target derives `superseded_by` and `status=superseded`. `stale` derived from `last_confirmed + window` against injected clock. `reconfirm(entryId, keyfile, {snapshot_hash, reproduction?, observation?})` by a trusted operator, never the submitter's, appends `reconfirmation` with the schema record shape (`reproduction` and `observation` present, null when unused), advances `last_confirmed`, and rotates the reconfirmer into the oldest of three read-share slots unless already holding one. Behavior reconfirm requires `reproduction` with `holds >= k`; observed non-behavior reconfirm requires `observation`.
Files: `src/supersede.ts`, `src/reconfirm.ts`, `src/derive.ts`, `test/lifecycle.test.ts`.
Test: category mismatch refused; old entry flips only when new one verifies; pricing stale at day 91; reconfirm clears stale and rotates oldest slot; same holder reconfirming rotates nothing; submitter's operator refused; behavior reconfirm without reproduction refused; behavior reconfirm at 7/10 refused.
Section: Freshness and decay; Incentives (slots). Depends: M9, M10.

## M12. Offline verify script
Builds: `nmk verify <entry.json> --events <events.jsonl> --operators <operators.json>`: schema, author signature, every approver signature, exclusion rules, hash chain, recompute every derived field and diff, recompute `snapshot_hash` from the archived raw capture when present under the entry's `norm_version`. Exit 0 clean, 1 with named diffs. This is the paper's "two files and one script".
Files: `src/verify.ts`, `src/cli.ts`, `test/verify.test.ts`, `fixtures/verified-entry/*`.
Test: fixture passes; hand-edited `status` fails naming the field; edited `claim` fails on author signature; dropped approver fails on recompute; broken chain fails; archived capture edited fails on snapshot recompute.
Section: Goals (4); Lifecycle, Seal. Depends: M11.

Demo checkpoint. Script `scripts/demo.sh`: maintainer seeds one entry, three fixture operators outside the maintainer's validate it, entry reaches verified, `nmk verify` exits 0.

## M13. Read API with signed receipts
Builds: fetch-handler server (Workers compatible). `GET /entry/:id` and `GET /entries?subject=&category=&status=&min_tier=&max_age=` return the entry plus a signed read receipt `{entry_id, at, counter}` from the maintainer key. `min_tier` filters on the sidecar effective tier when present, else `evidence_tier`. Daily `read_counts` event appended by `publishReadCounts(date)`.
Files: `src/api.ts`, `src/receipts.ts`, `src/server.ts`, `test/api.test.ts`.
Test: 404 unknown; filters apply; receipt verifies and counter increments; published count equals receipts issued.
Section: Training path, Frozen reader; Incentives, Money. Depends: M4. Parallel-safe after M4.

## M14. Seal: Merkle batches, mock witnesses, anchor stub
Builds: `sealBatch(now)` every policy interval over new events: Merkle root, `data/seals/<n>.json`, two fixture witness signatures, `entry.seal {position, inclusion_proof, sealed_at}`. Drafts and rejections seal too. `anchorDay(date)` writes the day's root to `data/anchors/<date>.json` (stub for external timestamp chain). `verifyInclusion`. `nmk verify` gains the seal check. Witness rule enforced: no two witnesses under one operator, maintainer ineligible.
Files: `src/seal.ts`, `src/merkle.ts`, `src/verify.ts`, `test/seal.test.ts`.
Test: inclusion proof verifies; earlier event modified breaks it; draft entry has a seal; maintainer key as witness refused; anchor file matches sealed root.
Section: Lifecycle, Seal; Limitations (witness set). Depends: M12.

## M15. Delta stream + sync receipts
Builds: `GET /delta?since=<position>&flatten=1&tier=`: events strictly by sealed position with inclusion proofs; flatten collapses supersession chains to current truth; overturned entries emit `{type:"unlearn", entry_id}`; response carries new head and one signed sync receipt covering every delivered entry; each delivered verified entry counts as a read.
Files: `src/delta.ts`, `src/api.ts`, `test/delta.test.ts`.
Test: two syncs from same position byte-identical; flatten returns newest only; overturned appears as unlearn; sync receipt lists every entry id; read counts increment per delivered entry.
Section: Training path, Delta stream; Paying. Depends: M13, M14.

## M16. Disputes and revalidation requests
Builds: `dispute(entryId, correctionCore, keyfile, stake)`: correction-category entry, dispute record `outcome=open`, stake debited from `data/standing.json` (operator) or a filing fee record (bare key). Extra exclusion: no signer of the original may validate the correction. Upheld sets target `overturned`, `overturned_by`, returns stake. Failed sets `outcome=failed`, forfeits stake. `requestRevalidation(entryId, keyfile)` stakes standing, assigns via M9 draw, capped per operator per window; change found pays requester, hold loses stake; request with citation upgrades to dispute.
Files: `src/dispute.ts`, `src/revalidation.ts`, `src/validate.ts`, `src/derive.ts`, `test/dispute.test.ts`.
Test: original signer refused; upheld overturns and refunds; failed forfeits; cap enforced; upgrade creates a dispute with `upgraded_from`.
Section: Lifecycle, Dispute and Revalidate. Depends: M11, M12.

## M17. Standing, clawback, holdback, seed fee
Builds: `computeStanding(operatorId, events)` by published formula in `src/policy.ts`: plus for approved submissions, validations (assigned weighted higher), rejections that hold, upheld challenges; minus for overturned signatures, failed challenges, wrong reconfirmations, missed assignments; decay paused flag. `accrue(readCountsEvent)` splits 15/5/5/5 into `data/ledger.jsonl` with 30-day holdback; overturn within holdback claws back; seed fee per completed validation at policy rate under cap, same holdback and clawback. Stale entries accrue half, other half to the bounty paid on reconfirm.
Files: `src/standing.ts`, `src/ledger.ts`, `src/policy.ts`, `test/incentives.test.ts`.
Test: standing recomputed from events equals stored; overturn inside 30 days claws back all four shares; outside claws back nothing and burns standing; stale half-rate and bounty payout on reconfirm; seed fee stops at cap; two independent recomputes agree.
Section: Incentives. Depends: M16.

## M18. Failure reports, drift attestation, confidence null
Builds: `reportFailure(entryId, keyfile, artifact_hash)`; threshold counts distinct verified operators only, opens `revalidation_opened`; report with citation upgrades via M16. `drawProbeSet(beacon, poolSnapshot, size)` from verified observed fresh entries; `attest(modelOperator, answers, threeScorers)` seals `{score, probe_hash, date}` with scorers not under the model's operator. `confidence` always null, `GET /entry/:id/confidence-inputs` exposes raw inputs.
Files: `src/reports.ts`, `src/attest.ts`, `src/confidence.ts`, `src/api.ts`, `test/reports.test.ts`.
Test: three bare-key reports do not open; three verified operators do; probe set deterministic; scorer under model operator refused; confidence null; inputs endpoint returns tier, test acceptance, counts, age ratio, dispute count, report count.
Section: Training path, Failure reports, Drift attestation, Confidence. Depends: M15, M17.

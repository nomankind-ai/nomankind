-- 0019_duplicate_key: the duplicate rule as a column and an index, and the
-- draws step's queue as a bounded one (M25, whitepaper Section 6 "Submit" and
-- decision D-085 -- the log refuses the mechanical duplicate at the door).
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0018 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Nothing here is a source of truth. Section 3: the log is the record. The
-- column below is a function of the entry's own signed core, recomputed by
-- src/duplicate.ts on every write of the row; drop it and the same values come
-- back.

-- The duplicate key, materialised.
--
-- The QA of 2026-09-12: the duplicate door read a subject's whole live history
-- on every submission -- 669 rows for 667 live entries, about 130 MB of JSON at
-- a hundred thousand -- because the rule lived only in code. The rule is four
-- fields: domain, subject, category, and the `after` value normalized under
-- step 4 of norm-v1.2. This column is the SHA-256, in hex, of the RFC 8785
-- canonical JSON of exactly those four, computed by `duplicateKeyHash` in
-- src/duplicate.ts and written by the one upsert every entry write goes through
-- (src/storage/repository.ts, `entryStatement`). A path that wrote the row
-- without the column would be a second source of truth about what a claim is,
-- which is exactly what this is not.
--
-- Nullable, and null means one thing only: a row written before this migration
-- and not yet backfilled. The norm rule is Unicode normalization and whitespace
-- folding over arbitrary text, which SQL cannot run, so the backfill is code:
-- `backfillDuplicateKeys` in src/storage/repository.ts recomputes the key from
-- each row's own entry_json through the same function the door uses, and the
-- sweep is what calls it: the `duplicates` step (src/worker/sweep.ts) fills at
-- most DUPLICATE_BACKFILL_PER_RUN rows a run and the next run continues, so a
-- migrated log catches up over the runs after the deploy rather than inside it,
-- and once nothing is left the step is one bounded read that finds nothing.
-- Every row written from here on carries its key by construction.
ALTER TABLE entries ADD COLUMN duplicate_key TEXT;

-- (duplicate_key, status): the door's whole question in one seek. "Is there a
-- live entry -- a draft or a verified one -- holding this claim?" is an
-- equality on the first column and a small set on the second, so the newest one
-- is found without reading a single entry_json.
CREATE INDEX entries_duplicate_key ON entries (duplicate_key, status);

-- The draws step's queue, bounded.
--
-- The QA of 2026-09-12: the sweep paged every draft in the table on every run,
-- so a draft nobody ever validated stayed in the working set forever. The step
-- now asks only for drafts submitted within DRAW_DRAFT_MAX_AGE_DAYS of the
-- run's clock (src/policy.ts), which is an equality on status and a range on
-- submitted_at; the third column is the keyset the pager resumes on, so a page
-- is a seek and the sort is the index's own.
CREATE INDEX entries_status_submitted_at
  ON entries (status, submitted_at, submitted_seq);

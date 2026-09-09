-- 0007_receipts: the placeholder `receipts` table becomes the read-receipt store.
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0006 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- 0001 declared `receipts` as a placeholder "so the storage shape is settled and
-- no later migration has to reshape a live table under load", and named M17 as
-- what fills it. It does, and the columns hold as written: for a row of kind
-- 'read', `seq` is the running counter the receipt carries, `entry_id` is the
-- entry that was read, `created_at` is the injected clock's ISO instant, and
-- `payload_json` is the whole signed receipt. Nothing is added and nothing is
-- reshaped — only the three indexes the read path needs.
--
-- Whitepaper Section 8, "The frozen reader": a read returns "a signed read
-- receipt naming the entry, the time, and a running counter". A running counter
-- is only worth anything if it runs: two readers served at the same instant must
-- not be handed the same number, or the day's published count could hide a read
-- behind a duplicate. This unique index is the guard, and it is the database's
-- job rather than the application's — an isolate cannot see what another isolate
-- is halfway through inserting, and a SELECT MAX(seq) followed by an INSERT is a
-- race however carefully it is written. The second writer's insert fails, and
-- src/storage/repository.ts turns that failure into ReceiptConflictError so the
-- caller re-reads the counter and signs again.
CREATE UNIQUE INDEX receipts_kind_seq ON receipts (kind, seq);

-- Section 9, Money: "Read counts are published to the sealed log daily." That
-- publication is one question — how many reads on this UTC day — and it starts
-- from a date rather than from a key. `created_at` is the injected clock's ISO
-- instant, always "<day>T...", so the day is the half-open text range from
-- "<day>T" to "<day>U" ('U' is the character after 'T'), which this index seeks
-- (src/storage/repository.ts, readCountsOn and readCounterRangeOn). A range, not
-- substr(...) = ?, because a function call over every row is a scan.
CREATE INDEX receipts_kind_created_at ON receipts (kind, created_at);

-- "Which receipts were issued for this entry?": what a reader auditing one
-- entry's earnings asks, and what the per-entry grouping of the daily count
-- reads. Without it that grouping is a full scan of every receipt ever issued.
CREATE INDEX receipts_kind_entry ON receipts (kind, entry_id);

-- 0016_receipt_counter: the running receipt counter is handed out by the
-- database, in one statement, instead of read and then written.
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0015 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Whitepaper Section 8, "The frozen reader": a read returns "a signed read
-- receipt naming the entry, the time, and a running counter", and Section 9
-- publishes the day's counts so "any reader can compare the receipts they hold
-- against the published counts". 0007 and 0008 made the unique index the guard
-- against two readers being handed the same number, and the door drew the
-- number with SELECT MAX(seq) and then inserted at it. That is a race by
-- construction — an isolate cannot see what another is halfway through
-- inserting — and the door paid for it with a retry loop that signed the
-- receipt again for the next number. Under real parallelism the loop runs out:
-- on the demo instance 42 of 50 parallel signed syncs were answered 503
-- receipt_conflict rather than a receipt.
--
-- So the number is allocated instead of guessed. One row, one counter, and
-- `UPDATE ... RETURNING` — the same single statement `api_keys.counter` is
-- drawn with (src/worker/access.ts, nextKeyCounter) — which D1's single writer
-- serializes: two isolates asking at the same instant are handed two numbers
-- because the database hands them out, and no isolate ever signs over a number
-- another already holds. The unique index stays exactly where it is as the
-- second guard.
--
-- The counter is the high-water mark of numbers handed out, not a count of
-- receipts. A request that dies between drawing its number and storing its
-- signed receipt leaves a gap, which is visible rather than silent — but not
-- from the day's `total`, which counts reads and not rows: one sync receipt can
-- be six reads or none. So the read_count payload publishes `receipts`, the
-- number of read and sync receipt rows issued that day
-- (src/storage/repository.ts, countReceiptsOn), beside `counter_first` and
-- `counter_last`, and `counter_last - counter_first + 1 - receipts` is how many
-- numbers were drawn and never handed over. A reused number would be the thing
-- that could hide a read, and that is what cannot happen here.
CREATE TABLE receipt_counter (
  id      TEXT PRIMARY KEY,  -- 'reads': the one counter read and sync receipts share
  counter INTEGER NOT NULL   -- the last number handed out; the next is this + 1
);

-- Seeded from the live table, so every receipt already issued on demo and on
-- production keeps the counter it carries and the next number continues from
-- it. Nothing is renumbered and nothing is rewritten: this reads `receipts` and
-- writes one row of its own. An empty log seeds 0, and the first number handed
-- out is then 1, exactly as `nextReadCounter` answered on an empty table.
INSERT INTO receipt_counter (id, counter)
SELECT 'reads', COALESCE(MAX(seq), 0) FROM receipts WHERE kind IN ('read', 'sync');

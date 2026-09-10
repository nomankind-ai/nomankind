-- 0010_ledger: what the money side needs to be queried (M21).
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0009 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Nothing here is a source of truth. Whitepaper Section 9: read counts are
-- published to the sealed log and "each day's published count is the number the
-- seal commits to and payouts are computed from", so every row and every column
-- below is an index into the log. Drop the lot and the same rows come back by
-- replaying the events (src/ledger.ts, src/standing.ts) — with one deliberate
-- exception, the payout, which records money that left through a provider and
-- can never be recomputed from anything.

-- The amount and its unit, promoted out of payload_json.
--
-- `ledger` as 0001 declared it carries the whole record as JSON and nothing to
-- sum. That was right while a row was a stake and no money moved (D-064): there
-- was nothing to add up. There is now — a payout is the sum of an operator's
-- released rows, and a balance is a sum over an entry's — and a sum through
-- json_extract is a scan of every row in the table.
--
-- `unit` is a column beside it because the amounts are not comparable: read
-- revenue is micro-USD, a stake is standing, a bare key's filing fee is cents,
-- and a query that summed them together would produce a number that means
-- nothing. Every read of `amount` filters on `unit`.
ALTER TABLE ledger ADD COLUMN amount INTEGER;
ALTER TABLE ledger ADD COLUMN unit TEXT;

-- Which share a row pays (submitter, validator, reconfirmer), the UTC day it is
-- about, and when it may leave: Section 9's thirty-day holdback, as an instant.
-- Null on every row that is not waiting on it — a withheld pool row, a clawback,
-- a payout, a reconciliation.
ALTER TABLE ledger ADD COLUMN role TEXT;
ALTER TABLE ledger ADD COLUMN "date" TEXT;
ALTER TABLE ledger ADD COLUMN available_at TEXT;

-- The payout row that took this row out of the ledger, by its id. Null while the
-- row is unpaid, which is what makes "what does this operator have coming"
-- answerable without reading the payouts and subtracting them.
ALTER TABLE ledger ADD COLUMN paid_by TEXT;

-- "What is this operator owed, and what of it has been released?": the read
-- behind every payout cycle. Partial on the unpaid rows, because a row that has
-- been paid can never come due again, so it is not in the index at all and the
-- seek walks one operator's open rows in holdback order.
CREATE INDEX ledger_operator_unpaid
  ON ledger (operator_id, available_at)
  WHERE paid_by IS NULL;

-- "What did the ledger do on this day?": the read behind the daily
-- reconciliation and behind every per-day report, seeking rather than scanning.
CREATE INDEX ledger_kind_date ON ledger (kind, "date");

-- The stake rows written before this migration carry their amount and unit
-- inside payload_json (src/stake.ts). Rederiving them would write exactly these
-- values, so the backfill is the cheap half of that: it copies what the record
-- already says rather than deciding anything.
--
-- The WHERE clause is not idempotence smuggled back in — a migration runs once,
-- and the tracking table is what says so. It is the filter: a reward row carries
-- a null amount on purpose (Section 9's pricing was M21's) and must stay null.
UPDATE ledger
   SET amount = json_extract(payload_json, '$.amount'),
       unit   = json_extract(payload_json, '$.unit')
 WHERE json_extract(payload_json, '$.amount') IS NOT NULL;

-- The bounty accruals written before this migration carry `amount_cents`, which
-- was always null: the field was a placeholder for pricing that did not exist
-- yet, and M21 is where it does. It is `amount_micros` now (src/bounty.ts),
-- because one read's share is a fraction of a cent and a record counted in cents
-- could not hold it. The key moves; the value it held — nothing — does not.
UPDATE ledger
   SET payload_json = json_remove(
         json_set(payload_json, '$.amount_micros', json('null')),
         '$.amount_cents'
       ),
       unit = 'micros'
 WHERE kind = 'bounty_accrual'
   AND json_type(payload_json, '$.amount_cents') IS NOT NULL;

-- Where a stepper says how far it has read.
--
-- The ledger steps are folds over the log — price a day's reads, claw back an
-- overturned entry, recompute standing — and every one of them has to know where
-- it stopped, or it would either redo the whole log every run or quietly skip
-- what arrived while it was working. One row per stepper, named by the stepper.
--
-- Not a source of truth either: a cursor that is lost or set back only makes a
-- step redo work it has already done, and every row it writes is idempotent by
-- id, so redoing it changes nothing.
CREATE TABLE ledger_state (
  name TEXT    PRIMARY KEY,
  seq  INTEGER NOT NULL
);

-- Section 9: "Standing is not a score nomankind assigns. It is derived from the
-- sealed public events by a published formula." So these two columns are a
-- cache and are named as one: `standing` is what the formula returned, and
-- `standing_seq` is the log position it was computed at, which is what makes the
-- number checkable — anyone can rerun src/standing.ts over the log up to that
-- position and get the same one. Both null until the first standing step runs,
-- and a page that finds them null recomputes rather than showing a zero.
ALTER TABLE operators ADD COLUMN standing INTEGER;
ALTER TABLE operators ADD COLUMN standing_seq INTEGER;

-- 0023_money_removed: the tables and columns the money code left behind
-- (decision D-127 item 2, whitepaper "Money" -- the record is free from the
-- seal, so nothing here is sold, metered or paid out).
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0022 are closed; this
-- file drops what nothing reads, writes or exports any more, and adds the one
-- column that replaces a provider column still doing work.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- What is NOT dropped, and why. `quota` is a read counter and not a money
-- table: the free and keyed caps are counted in it and always were. `receipts`
-- keeps `key_id` and `key_counter`, which a keyed reader's own receipt numbers
-- are. The ledger keeps every row it holds -- sealed history is not deleted --
-- and keeps `amount`, `unit`, `role`, `date` and `available_at`, because
-- `GET /ledger`, the operator page and the mirror's `ledger.jsonl` all still
-- read them off the rows the months the record was sold wrote. `read_count`
-- events and their per-key counts are untouched: mirror importers must parse
-- them forever.
--
-- THE FIRST TABLE REBUILD IN THIS REPOSITORY, AND WHAT TO DO IF IT STOPS HALF
-- WAY. The deploy runs `wrangler d1 migrations apply --remote`, which does not
-- promise that one file's statements land as one transaction, so this file is
-- ordered so that a stop leaves the database readable and the rest of it
-- hand-appliable. The rebuild comes first, and nothing before the two renames
-- is destructive:
--
--   * stopped after CREATE or after the INSERT: `api_keys` is untouched and
--     readable, and the copy is standing beside it under a name nothing reads.
--     Recover by hand with `DROP TABLE api_keys_without_provider;` and re-run
--     the file.
--   * stopped between the two renames -- the one statement in this file after
--     which `api_keys` does not exist: every row is still there, under
--     `api_keys_without_provider`. Recover with
--     `ALTER TABLE api_keys_without_provider RENAME TO api_keys;` and then
--     apply the statements after it by hand; or rename `api_keys_with_provider`
--     back to `api_keys`, drop the copy, and re-run the file.
--   * stopped after the second rename: `api_keys` is readable and already the
--     new shape. Apply the statements after the stop by hand; a re-run would
--     fail on a table it has already dropped.
--
-- The `d1_migrations` row is written only when every statement has landed, so
-- a stop always leaves the file unrecorded and a re-run always starts at the
-- top: that is why the recovery above is a hand step and not another migration.

-- The keys table, rebuilt without the payment provider's three columns.
--
-- `customer`, `subscription` and `checkout_session` were a paid loop's
-- bookkeeping. Two of them were already dead the day the checkout and webhook
-- doors were retired; the third was not, because the free door filed one key
-- per client per UTC day under a synthetic `checkout_session` and the unique
-- index on it was the rule. So the rule moves to a column that says what it is:
-- `client_day` is the hashed client and the UTC day, and its unique index is
-- what makes two requests racing for today's key produce one.
--
-- A rebuild rather than three DROP COLUMNs because SQLite refuses to drop a
-- column a UNIQUE constraint names, and two of these are unique. Every key ever
-- minted is carried over, hash, tier, status, counter and dates intact, so no
-- reader's key stops working; a key minted at the free door keeps its day
-- through the substring below -- `free:day:` is nine characters, so the day and
-- the digest start at the tenth -- and a key from the paid era carries a null,
-- which the partial index leaves alone.
--
-- The original is renamed out of the way rather than dropped, and dropped only
-- once the new table is in place: a stop before that last statement leaves
-- every row that was ever in this table present under one name or the other.
CREATE TABLE api_keys_without_provider (
  id         TEXT PRIMARY KEY,           -- "key_" + 16 lowercase hex
  key_hash   TEXT NOT NULL UNIQUE,       -- sha256 hex of the secret
  tier       TEXT NOT NULL,
  status     TEXT NOT NULL,              -- active; a pre-D-127 row may say otherwise
  client_day TEXT,                       -- "<client digest>:<YYYY-MM-DD>", null for a pre-D-127 key
  counter    INTEGER NOT NULL DEFAULT 0, -- the key's own receipt counter (last issued)
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

INSERT INTO api_keys_without_provider
  (id, key_hash, tier, status, client_day, counter, created_at, updated_at)
SELECT id,
       key_hash,
       tier,
       status,
       CASE
         WHEN checkout_session LIKE 'free:day:%'
           THEN substr(checkout_session, 10)
         ELSE NULL
       END,
       counter,
       created_at,
       updated_at
  FROM api_keys;

ALTER TABLE api_keys RENAME TO api_keys_with_provider;

ALTER TABLE api_keys_without_provider RENAME TO api_keys;

-- One key per client per UTC day (D-127), enforced rather than checked: the
-- door's own lookup is the courteous answer and this is the rule. Partial,
-- because every key minted before this migration carries a null day and a plain
-- unique index would let exactly one of them exist.
CREATE UNIQUE INDEX api_keys_client_day
  ON api_keys (client_day) WHERE client_day IS NOT NULL;

-- And only now the original, whose every row is in the table above.
DROP TABLE api_keys_with_provider;

-- The payment provider's own two tables. Nothing writes them: the webhook door
-- and the metering step are gone, and neither table was ever a source of truth
-- about the log -- one recorded that a provider message had been acted on, the
-- other that a key-day had been reported to a meter. The log is untouched by
-- their going.
DROP TABLE stripe_events;

DROP TABLE meter_reports;

-- The metering step's cursor, with the step it indexed.
DELETE FROM ledger_state WHERE name = 'metering';

-- The payout stamp on a ledger row, and the index that read it.
--
-- `paid_by` named the payout row that took an accrual out of the ledger. There
-- are no payouts to name any more and nothing reads the column: it is not on
-- `LedgerRow`, no door serves it and the mirror's fold never saw it. The index
-- goes first because SQLite will not drop a column a partial index's WHERE
-- clause names.
DROP INDEX ledger_operator_unpaid;

ALTER TABLE ledger DROP COLUMN paid_by;

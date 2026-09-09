-- 0005_freshness: the freshness and supersession columns the sweep reads.
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0004 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Whitepaper Section 7, "Freshness and decay": past its window an entry stays
-- verified but shows as stale, and the withheld half of its earnings builds up
-- as a reconfirmation bounty. Something has to find those entries when the day
-- turns, and "which entries went stale?" is a question about every entry at
-- once — the only other query in the system, beside the assignment sweep, that
-- starts from a date rather than from an entry. Answering it out of entry_json
-- means parsing every row in the table on every sweep.
--
-- So the three fields the sweep and the supersession lookup need come out
-- beside the JSON, exactly as subject, category and status already do
-- (0001_init, and putEntry's comment in src/storage/repository.ts). They are
-- copies, never a second source of truth: derivation computes stale, expires_at
-- and superseded_by from the events, and rederiving an entry and storing it
-- again rewrites the columns and the JSON together.
ALTER TABLE entries ADD COLUMN stale INTEGER NOT NULL DEFAULT 0;
ALTER TABLE entries ADD COLUMN expires_at TEXT;
ALTER TABLE entries ADD COLUMN supersedes TEXT;

-- The rows already stored carry all three inside entry_json, so the copies are
-- filled from the JSON rather than by rederiving the whole table: the values are
-- the same either way, and this way the migration needs nothing but SQLite.
-- `stale` is a JSON boolean and the column is 0/1, so it is normalised here;
-- expires_at and supersedes are a string or null in the JSON and a string or
-- null in the column, so they copy across as they are.
UPDATE entries SET
  stale = CASE WHEN json_extract(entry_json, '$.stale') THEN 1 ELSE 0 END,
  expires_at = json_extract(entry_json, '$.expires_at'),
  supersedes = json_extract(entry_json, '$.supersedes');

-- "Which verified entries have run out of window?": the staleness sweep's one
-- read. Partial, on exactly the rows the sweep can act on — an entry already
-- marked stale cannot go stale again, and an event-category entry has no
-- expires_at and never will — so the seek walks the fresh, windowed entries in
-- expiry order and the rest are not in the index at all.
CREATE INDEX entries_stale_due
  ON entries (expires_at)
  WHERE stale = 0 AND expires_at IS NOT NULL;

-- "What supersedes this entry?": the read behind a superseded entry's pointer.
-- Partial, because supersedes is null on nearly every entry and a full index
-- would be mostly nulls.
CREATE INDEX entries_supersedes
  ON entries (supersedes)
  WHERE supersedes IS NOT NULL;

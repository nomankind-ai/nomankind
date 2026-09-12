-- 0018_counters: the numbers the public pages show, counted once per sweep, and
-- the three columns that let them be counted from an index (M25, whitepaper
-- Section 3 "the log" -- every number a page shows is a view of the log).
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0017 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Nothing here is a source of truth. Section 3: the log is the record, and every
-- number below is a view of it. Drop this table and the three columns and the
-- same numbers come back -- the next sweep recounts them all, and the columns
-- are what the JSON beside them already says. What this buys is that a reader
-- does not pay for the recount: the QA of 2026-09-12 found the home, entries,
-- domains and status pages counting whole tables per view, twice over for the
-- two conditions no index could serve (`witnesses_json <> '[]'` and
-- `json_extract(operator_json, '$.trusted')`).

-- One row per counter, with its integer value, the sealed position it was
-- counted at, and the run's instant.
--
-- One row per name and not one JSON blob, because a blob is a value a query
-- cannot filter and this table is read by name: the status gather wants five of
-- these rows and the domains page wants the two per slug. The per-domain
-- counters are named 'domain:<slug>:entries' and 'domain:<slug>:trusted', which
-- is why the key is TEXT and not an enum -- a domain added to the registry adds
-- rows here and needs no migration.
--
-- `position` is what makes a row checkable: recount the log up to it and the
-- same number must come back. Every row of one run carries the same position
-- and the same `updated_at`, because the run writes them in one batch and a
-- page that showed two counters from two different positions would be showing a
-- log that never existed.
CREATE TABLE counters (
  name       TEXT PRIMARY KEY,
  value      INTEGER NOT NULL,
  position   INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);

-- Staleness, on its own.
--
-- 0005 added `stale` beside the JSON and indexed (expires_at) WHERE stale = 0,
-- which is the sweep's queue of entries that could still go stale. It is no use
-- to the question the pages ask -- how many entries are stale right now -- and
-- that count was a whole-table scan. This index is that count, and the entries
-- listing's `stale` filter with it.
CREATE INDEX entries_stale ON entries (stale);

-- Trust, as a column.
--
-- Section 11: trusted status is granted by an `operator_trusted` event and
-- recorded on the row by whoever recomputed it. The row already carried it,
-- inside `operator_json`, where counting it meant json_extract over every
-- operator in the table. This column is that same value, materialised, so the
-- count and the directory's list are an index seek.
--
-- It is written in the same batch as `operator_json`, by the one upsert every
-- write goes through (src/storage/repository.ts, `operatorStatement`, which
-- `putOperator`, `registerOperator`, `trustOperator` and `recordTrustChange` all
-- use), and it is never set from anywhere else. A path that wrote the JSON
-- without the column would be a second source of truth about trust, which is
-- exactly what this is not: the events are the record, the JSON is the cache,
-- and this column is the JSON's index.
ALTER TABLE operators ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0;

-- The backfill, in the truth the count used: `json_extract` of a stored `true`
-- is truthy, of a stored `false` is false, and of a row that never carried the
-- field at all is null and so not trusted. Every operator already registered
-- keeps exactly the trust it had.
UPDATE operators
   SET trusted = CASE WHEN json_extract(operator_json, '$.trusted') THEN 1 ELSE 0 END;

-- (trusted, id): the count seeks the first column and the directory's list of
-- trusted ids reads the second straight off the index, in id order, without
-- touching a row.
CREATE INDEX operators_trusted ON operators (trusted, id);

-- Countersignature, as a column, for the same reason.
--
-- `witnesses_json <> '[]'` is a comparison against a TEXT column that no index
-- can serve, and the status page asked it on every view. This column is the
-- same fact -- whether the seal carries at least one countersignature -- written
-- in the same batch as the JSON it summarises (`putSeal`, `recordSeal` and
-- `setSealWitnesses`, and nowhere else).
ALTER TABLE seals ADD COLUMN witnessed INTEGER NOT NULL DEFAULT 0;

UPDATE seals SET witnessed = CASE WHEN witnesses_json <> '[]' THEN 1 ELSE 0 END;

-- The status page's question: how many of the log's seals carry one. A plain
-- index rather than the partial one below, because the two are different
-- questions -- this one seeks the countersigned seals, which is most of the
-- table and grows with it, and the partial index holds only the handful still
-- waiting.
CREATE INDEX seals_witnessed ON seals (witnessed);

-- The sweep's work queue, as a partial index: the seals still waiting on the
-- outside world, which is a handful of rows in a table that only grows. The
-- index's condition is written exactly as `unwitnessedSeals` asks it, because
-- SQLite uses a partial index only where the query's own WHERE implies it, and
-- the seq in the index is what makes "oldest first, one page" a seek.
CREATE INDEX seals_unfinished ON seals (seq)
  WHERE witnessed = 0 OR registry_json IS NULL;

-- 0013_status: what each step of the sweep last did, so the status page can say
-- whether the clockwork is running (decision D-076).
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0012 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Nothing here is a source of truth about the log. Every row is the sweep's own
-- account of one of its steps -- when it last ran, when it last got through
-- without refusing, and what it refused with -- and drop the table and the log
-- is exactly what it was. What is lost is only the ability to say when a step
-- last ran, which no event records because a step that did nothing appends
-- nothing. That is the whole reason the table exists: "the sweep has not run
-- for forty minutes" is not a question the events table can answer.

-- One row per step, upserted at the end of every run. The step name is the key
-- because there is exactly one current answer per step: this table is a status
-- board and never a history, and a run's own history is the sealed log.
--
-- `last_run_at` is every run's instant, so a run that reached the step at all
-- moves it. `last_ok_at` and the two skip columns are carried forward by the
-- upsert when a run has nothing new to say about them, which is what lets the
-- page ask "when did this last work" of a step that has been refusing since.
--
-- `detail_json` is that step's part of the sweep's own report, plus the few
-- facts the status rules need and the report does not carry (the beacon round
-- the draws read, the sealed head the standing step recomputed against). JSON
-- rather than columns because the shape differs per step and none of it is ever
-- queried on -- the page reads the row it already has by key.
--
-- "trigger" is quoted everywhere it appears: it is a SQLite keyword, and an
-- unquoted column of that name is a syntax error rather than a column.
CREATE TABLE sweep_steps (
  step             TEXT PRIMARY KEY,
  last_run_at      TEXT NOT NULL,
  last_ok_at       TEXT,
  last_skip_reason TEXT,
  last_skip_at     TEXT,
  detail_json      TEXT NOT NULL,
  "trigger"        TEXT NOT NULL
);

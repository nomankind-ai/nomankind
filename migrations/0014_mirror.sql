-- 0014_mirror: what the daily export pushed, and where it can be read
-- (M23, whitepaper Section 11 "Deployment and status").
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0013 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Nothing here is a source of truth about the log. The mirror repository is the
-- record of what was exported; this table only says which day's export has
-- already been made, so a second sweep on the same day does not push again, and
-- where the last one landed, so /mirror/latest and the status page can point at
-- it. Drop the table and the mirror is untouched -- the next sweep simply
-- exports the day again, which is idempotent by construction because two
-- exports of the same sealed head are byte-identical.

-- One row per UTC day. The day is the key because there is exactly one export
-- per day: this is a record of the days that are done, never a history of
-- pushes.
--
-- `head` is the sealed position the export was built at and `seal_seq` is the
-- newest seal's own seq, so a reader can tell which sealed head a day's
-- directory describes without fetching it. `files_changed` is 0 on a day whose
-- bytes were already in the repository, which is a real export and not a
-- failure: the day is current, and no commit was needed to say so.
CREATE TABLE mirrors (
  date          TEXT PRIMARY KEY,
  exported_at   TEXT NOT NULL,
  commit_sha    TEXT NOT NULL,
  tree_sha      TEXT NOT NULL,
  head          INTEGER NOT NULL,
  seal_seq      INTEGER NOT NULL,
  entries       INTEGER NOT NULL,
  files_changed INTEGER NOT NULL,
  url           TEXT NOT NULL,
  raw_url       TEXT NOT NULL
);

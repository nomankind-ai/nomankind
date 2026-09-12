-- 0017_standing_cursor: the standing fold's cursor, and the mirror's claim on
-- the day (M25, whitepaper Section 9 "Standing" and Section 11 "the daily
-- mirror" as amended by D-100).
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0016 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Nothing here is a source of truth. Section 9: standing "is derived from the
-- sealed public events by a published formula, so anyone can recompute anyone's
-- standing from the log and get the same number." Drop this table and the same
-- numbers come back by replaying the log -- the next sweep finds no cursor and
-- folds the whole thing. What the table buys is that the sweep does not have to:
-- with the counts and the position they cover written down, a run folds the
-- events after that position and continues, instead of reading every sealed
-- event every five minutes.

-- One row per operator: the accumulator src/standing.ts folds, in the columns
-- its StandingCounts names, plus the three totals and the position they cover.
--
-- Columns and not a JSON blob, because the point of storing this is that the
-- fold can continue from it: a blob is a rendering of an answer, and a fold
-- resumes from an accumulator. `position` is what makes the row checkable --
-- rerun the published formula over the log up to it and every number here must
-- come back -- and it is what the next run reads the log after.
--
-- `earned`, `burned` and `locked` are stored rather than derived because two of
-- them are not reconstructible from the counts: a lock is an open stake and a
-- burn is a forfeit at a rate the counts do not carry. `standing` and
-- `available` are not stored at all: they are earned - burned and standing -
-- locked, and a column that can disagree with its own definition is a bug
-- waiting for a reader.
CREATE TABLE operator_standing (
  operator                TEXT PRIMARY KEY,
  position                INTEGER NOT NULL,
  earned                  INTEGER NOT NULL,
  burned                  INTEGER NOT NULL,
  locked                  INTEGER NOT NULL,
  validations_volunteered INTEGER NOT NULL,
  validations_assigned    INTEGER NOT NULL,
  validations_reproduced  INTEGER NOT NULL,
  attestations_scored     INTEGER NOT NULL,
  submissions_verified    INTEGER NOT NULL,
  disputes_upheld         INTEGER NOT NULL,
  revalidations_changed   INTEGER NOT NULL,
  overturned              INTEGER NOT NULL,
  missed                  INTEGER NOT NULL,
  forfeits                INTEGER NOT NULL
);

-- The day's export, claimed before it is pushed.
--
-- 0014 wrote the mirrors row only after a successful push, so a run killed
-- halfway through an export left no trace and every later run that day started
-- the whole export again. The claim is the fix: a row goes in `pending` when the
-- export starts and is updated to `pushed` with the commit when it lands. A
-- pending row younger than one sweep interval is a run that is still going and
-- the next run stands down; an older one is a run that died, and the next run
-- takes the day over. A failed push leaves the row pending with its reason in
-- the report, exactly as a refused export has always been reported.
--
-- `state` defaults to 'pushed' so every row 0014 wrote is what it always was: a
-- day that is exported. `started_at` is null for those, because nobody recorded
-- when they began, and a claim writes it.
ALTER TABLE mirrors ADD COLUMN state TEXT NOT NULL DEFAULT 'pushed';
ALTER TABLE mirrors ADD COLUMN started_at TEXT;

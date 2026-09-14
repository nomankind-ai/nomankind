-- 0022_cosign: who has co-signed with whom, and how often the two agreed
-- (D-119, whitepaper Section 3 "the log" -- every number a page shows is a view
-- of the log, and Section 5, the operator is the unit of accountability).
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0021 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- The question this answers is a reader's, from the demo test: how do I tell
-- three independent confirmations from three copies of one procedure. The log
-- has always held the answer -- the `validation` and `reconfirmation` events say
-- who signed what -- but only as events, so asking it meant folding the whole
-- log. This table is that fold, made once a run by the counters step.
--
-- Nothing here is a source of truth. Drop the table and the same numbers come
-- back: the next sweep finds no cursor and folds the sealed log from the start.

-- One row per ordered pair of operators that have both signed the same entry.
--
-- Ordered, so each pair is stored twice -- (a,b) and (b,a) -- because both reads
-- this exists for are "for this operator, who has it co-signed with": the
-- directory counts the rows of one operator and the operator page lists them
-- newest first. Storing the pair once under a sorted key would make both of
-- those an OR across two columns, which no index serves, and the point of this
-- table is that a page view issues no scan at all. Two rows per pair against a
-- dimension that is operators-squared and not log-sized is the cheap side of
-- that trade.
--
-- `both` is the entries the two have both signed, `agreed` the ones their
-- decisions matched on and `opposed` the ones they did not; agreed + opposed is
-- both, and it is stored rather than derived because it is what the page's
-- column is and a reader checking one number should not have to add two.
--
-- `through_seq` is what makes the row checkable: fold the sealed events up to it
-- and the same three numbers must come back. It is also the run's cursor --
-- see `cosign:through` in the counters table -- so a run folds what it has not
-- folded yet rather than the log.
--
-- `newest_entry_id` is the newest entry the two both signed and `newest_seq` the
-- position at which the second of them signed it. The entry id is what the page
-- links to, so a reader can leave the pair and go look at the record itself;
-- the seq is what the page orders by. One entry and not a list, because a list
-- inside a row is an unbounded column, and the entries a pair shares are the
-- entry pages' own business.
CREATE TABLE cosign_pairs (
  operator_a      TEXT NOT NULL,
  operator_b      TEXT NOT NULL,
  both            INTEGER NOT NULL,
  agreed          INTEGER NOT NULL,
  opposed         INTEGER NOT NULL,
  through_seq     INTEGER NOT NULL,
  newest_entry_id TEXT NOT NULL,
  newest_seq      INTEGER NOT NULL,
  PRIMARY KEY (operator_a, operator_b)
);

-- The operator page's own read: this operator's co-signers, newest pair first,
-- one page of them. The primary key above already serves the directory's count
-- (one operator, count the rows) and this serves the ordering, so neither read
-- touches a row it does not show.
CREATE INDEX cosign_pairs_newest ON cosign_pairs (operator_a, newest_seq DESC);

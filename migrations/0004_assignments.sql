-- 0004_assignments: the answered half of an assignment's life.
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0003 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Lifecycle of an entry, Validate: "An assigned validator has seventy-two hours
-- to respond. A miss costs standing, and the next beacon round draws a
-- replacement." 0001 gave an assignment one way to close, `missed_seq`, which
-- says the window ran out. It has two: the validator can answer. `answered_seq`
-- names the `validation` event that answered it, so the answer is a position in
-- the log rather than a flag someone set, exactly as the miss is.
--
-- Without this column the sweep cannot tell the two apart. An answered
-- assignment with no missed_seq still reads as open, so the sweep would keep
-- offering it as due and, once its deadline passed, would seal an
-- assignment_missed against a validator who responded on time.
ALTER TABLE assignments ADD COLUMN answered_seq INTEGER;

-- "Which assignments have run out of time?": the sweep's one read, and the only
-- query in the system that starts from a deadline rather than from an entry.
-- Partial, on exactly the rows the sweep can act on: an assignment already
-- closed — missed or answered — can never come due again, so it is not in the
-- index at all and the seek walks the open ones in deadline order.
CREATE INDEX assignments_due
  ON assignments (deadline)
  WHERE missed_seq IS NULL AND answered_seq IS NULL;

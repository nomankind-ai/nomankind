-- 0009_disputes: what a dispute, a revalidation and a stake need to be queried.
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0008 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Nothing here is a source of truth. Every column below is an index into the
-- event log: drop the three of them and the same answers come back by replaying
-- the events (src/derive.ts, src/stake.ts). They exist because the questions
-- they answer — "which entry does this correction dispute", "which revalidation
-- checks have run out of time", "what did this entry's stakes do" — cannot be
-- asked of the events table without scanning it, and scanning the log is the
-- one thing the storage layer exists to prevent.

-- Whitepaper Section 6, "Dispute": "A challenge is itself an entry, in the
-- correction category ... The original stays in the log, marked overturned,
-- linked to its correction." The link runs both ways: the target's
-- `overturned_by` is derived from its own events, and this column is the other
-- direction — the correction entry says which entry it was filed against.
--
-- Null for every entry that is not a filed dispute, correction-category entries
-- included: a correction can be submitted on its own, and only one filed as a
-- dispute carries the target here.
ALTER TABLE entries ADD COLUMN dispute_of TEXT;

-- "Which corrections were filed against this entry?": the read behind the
-- target's dispute list. Partial, on exactly the rows that are disputes, so the
-- index holds one row per filed dispute rather than one per entry in the log,
-- and ordered by submitted_seq so the answer is in filing order without a sort.
CREATE INDEX entries_dispute_of
  ON entries (dispute_of, submitted_seq)
  WHERE dispute_of IS NOT NULL;

-- Section 6, "Revalidate": a request "is assigned at random to a trusted
-- operator", with the same seventy-two hours and the same miss as a validation
-- assignment. It is the same shape of row, so it goes in the same table rather
-- than a second one that would need its own sweep and its own miss handling.
--
-- `purpose` is what tells the two apart. It defaults to 'validation' so every
-- row 0001 through 0008 wrote keeps the meaning it already had, and NOT NULL so
-- a row can never be silently neither. The sweep and the open-assignment lookups
-- filter on it: a revalidation draw must not answer an entry's validation
-- assignment, and a validation must not close a revalidation check.
ALTER TABLE assignments ADD COLUMN purpose TEXT NOT NULL DEFAULT 'validation';

-- The `revalidation_requested` event this assignment answers, by its position in
-- the log. Null on a validation assignment, which answers a submission and not a
-- request.
ALTER TABLE assignments ADD COLUMN request_seq INTEGER;

-- "Which revalidation checks have run out of time?", the mirror of 0004's
-- assignments_due for the other purpose. Partial on the open rows for the same
-- reason: an assignment already closed — missed or answered — can never come due
-- again, so it is not in the index at all and the seek walks the open ones of
-- one purpose in deadline order.
CREATE INDEX assignments_purpose_due
  ON assignments (purpose, deadline)
  WHERE missed_seq IS NULL AND answered_seq IS NULL;

-- Section 6: "Filing takes a stake ... An upheld challenge returns the stake,
-- pays the challenger", and a failed one forfeits it. Those rows are ledger
-- rows (src/stake.ts) and they are about an ENTRY, where every ledger row before
-- them was about an operator: `ledger` as 0001 declared it has operator_id and
-- no entry_id, and a bounty accrual has been found through json_extract ever
-- since. A stake is looked up per entry on the entry page, so it gets the
-- column rather than the scan.
--
-- Nullable, because the read-share accounting M21 fills this table with is not
-- entry-scoped in every row: a payout to an operator covers many entries.
ALTER TABLE ledger ADD COLUMN entry_id TEXT;

-- "What did this entry's stakes do?": the read behind the entry page's dispute
-- panel, in log order, seeking rather than scanning.
CREATE INDEX ledger_entry ON ledger (entry_id, seq);

-- The sidecar gained `revalidations` in this milestone (src/derive.ts). Every
-- row written before it has a sidecar_json without the key, and a page that
-- reads the list would meet undefined instead of an empty array. Derivation
-- would put the key back, but only for entries something later touches, and the
-- untouched ones are the whole stored corpus.
--
-- So the backfill is here, where it runs once before the Worker that needs it
-- goes live. It is not a source of truth either: it writes exactly what
-- rederiving those entries would write, which for an entry nobody has ever
-- asked a check of is the empty list.
--
-- The WHERE clause is not idempotence smuggled back in — a migration runs once,
-- and the tracking table is what says so. It is the filter: a row that already
-- carries the key carries a derived value, and overwriting it with [] would
-- destroy a real answer.
UPDATE entries
   SET sidecar_json = json_set(sidecar_json, '$.revalidations', json('[]'))
 WHERE json_type(sidecar_json, '$.revalidations') IS NULL;

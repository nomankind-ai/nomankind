-- 0011_attestations: what a drift attestation needs to be queried (M22).
--
-- Decision D-022 and the PoC retrospective's DEPLOY-1: migrations are numbered,
-- forward-only, applied by the deploy workflow with wrangler before the Worker
-- goes live, and never edited after merge. 0001 through 0010 are closed; this
-- file adds and never reshapes.
--
-- No IF NOT EXISTS anywhere: idempotence belongs to the d1_migrations tracking
-- table, not to the SQL. A migration that ran twice is a bug in the runner, and
-- IF NOT EXISTS would hide it.
--
-- Nothing here is a source of truth. Whitepaper Section 8, "Drift attestation":
-- "the score and the probe hash are sealed with a date", and what is sealed is
-- the event log. Drop both tables below and the same rows come back by replaying
-- the four attestation events (src/attest.ts, `deriveAttestation`). They exist
-- because the questions they answer -- "does this model already have an
-- attestation open", "which attestations have run out of time", "what has this
-- operator attested and scored" -- cannot be asked of the events table without
-- scanning it, and scanning the log is the one thing the storage layer exists to
-- prevent.

-- One attestation. `attestation_json` holds the derived record exactly as
-- `deriveAttestation` produced it, and every column beside it is a copy of a
-- field already inside that record, kept out so the listings can filter and
-- order without parsing every row -- the same arrangement `entries` has carried
-- since 0001, and never a second source of truth.
--
-- `model` is the model's own agent id and `model_operator` the operator that
-- answers for it, null for an agent bound to nobody: Section 8 asks for scorers
-- "none under the model's operator", which is a condition on a value that may
-- not exist, and a model whose key answers to nobody excludes nobody.
--
-- `answers_json` is the model's answers themselves, which the log deliberately
-- does not carry: only `answers_hash` is sealed (src/events.ts), because the
-- answers can be long and what the three scorers must agree about is that they
-- scored the same ones. So this column is the one place they live, and it is the
-- one column here that is not recomputable from the log -- like the payout row
-- 0010 added, and for the same honest reason.
--
-- `score_agreed` is the median the derived record published, and "date" the UTC
-- day the last score landed: the date the attestation is "as of". Both null
-- until every drawn scorer has signed.
CREATE TABLE attestations (
  id               TEXT    PRIMARY KEY,
  model            TEXT    NOT NULL,
  model_operator   TEXT,
  status           TEXT    NOT NULL,
  probe_hash       TEXT    NOT NULL,
  probe_count      INTEGER NOT NULL,
  requested_seq    INTEGER NOT NULL,
  requested_at     TEXT    NOT NULL,
  deadline         TEXT    NOT NULL,
  answers_json     TEXT,
  answers_hash     TEXT,
  scored_seq       INTEGER,
  score_agreed     INTEGER,
  "date"           TEXT,
  attestation_json TEXT    NOT NULL
);

-- "What has this operator's model attested?": the operator page's first table,
-- in log order, seeking rather than scanning.
CREATE INDEX attestations_operator_requested
  ON attestations (model_operator, requested_seq);

-- "Which attestations have run out of time?": the sweep's one read, the mirror
-- of 0004's assignments_due and 0009's assignments_purpose_due. Not partial,
-- because the states that can still come due -- open and answered -- are two of
-- the four rather than the absence of a column, so the status leads the key and
-- the seek walks one status in deadline order.
CREATE INDEX attestations_status_deadline ON attestations (status, deadline);

-- "Does this model already have an attestation open?": the check behind the
-- request route's 409, and what makes "one model attests at most once per beacon
-- round" a lookup rather than a scan of every attestation ever made.
CREATE INDEX attestations_model_status ON attestations (model, status);

-- The three drawn scorers, one row each. A row and not a JSON list inside
-- `attestations`, because the question runs the other way as often as it runs
-- this way: an operator's page asks what it was drawn to score, and a list
-- inside another table could only answer that by scanning.
--
-- Section 5, Identity and operators: the operator is the unit, so the primary
-- key is (attestation, operator) -- one operator scores an attestation once,
-- whichever of its agents signs -- and `agent` is the key the draw resolved for
-- it, carried so the score route can check the signing key against the draw.
--
-- `scored_seq` is the position of that scorer's `attestation_scored` event, null
-- until it signs, so "who has not scored yet" is a column and not a fold.
CREATE TABLE attestation_scorers (
  attestation TEXT    NOT NULL,
  operator    TEXT    NOT NULL,
  agent       TEXT    NOT NULL,
  scored_seq  INTEGER,
  PRIMARY KEY (attestation, operator)
);

-- "What was this operator drawn to score?": the operator page's second table.
-- The primary key already orders by (attestation, operator) and cannot answer
-- this one, so the operator leads its own index.
CREATE INDEX attestation_scorers_operator
  ON attestation_scorers (operator, attestation);
